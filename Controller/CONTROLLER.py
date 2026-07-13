

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
import time
import threading
from ast import literal_eval
from flask import Flask, request, jsonify


from monitor import MonitoringModule
from policy import PolicyModule
from enforcement import EnforcementModule


class SimpleSwitch13(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    FLOW_WINDOW_SEC = 1.0 # Finestra temporale per il calcolo delle statistiche dei flussi
    FLOW_PKT_THRESHOLD = 350
    FLOW_BLOCK_SECONDS = 15
    STATS_POLL_SEC = 1.0
    ADAPTIVE_THRESHOLD_ENABLED = True
    ADAPTIVE_HISTORY_SIZE = 12
    ADAPTIVE_MULTIPLIER = 1.7
    ADAPTIVE_MIN_SAMPLES = 3
    WHITELIST_MACS = set() #
    WHITELIST_ETHERTYPES = { # Lista di tipi di Ethernet da whiteliste
        ether_types.ETH_TYPE_ARP,
        ether_types.ETH_TYPE_LLDP,
    }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs) #super() chiama il costruttore della classe base RyuApp, inizializzando il framework Ryu e registrando l'applicazione come un'applicazione Ryu.

        # Dizionario: {dpid: {mac: porta}} dpid è l'identificatore dello switch, mac è l'indirizzo MAC sorgente e porta è la porta dello switch a cui è connesso l'host con quell'indirizzo MAC.
        self.mac_to_port = {} #questo dizionario viene utilizzato per implementare il comportamento di switching del controller, consentendo di inoltrare i pacchetti verso le porte corrette in base agli indirizzi MAC sorgente e destinazione.
        # Switch connessi per polling statistiche
        self.datapaths = {}
        
        
        self.monitoring_module = MonitoringModule(self, stats_poll_interval_sec=self.STATS_POLL_SEC)
        self.policy_module = PolicyModule(
            self,
            self.monitoring_module,
            flow_window_sec=self.FLOW_WINDOW_SEC,
            flow_pkt_threshold=self.FLOW_PKT_THRESHOLD,
            flow_block_seconds=self.FLOW_BLOCK_SECONDS,
            adaptive_threshold_enabled=self.ADAPTIVE_THRESHOLD_ENABLED,
            adaptive_history_size=self.ADAPTIVE_HISTORY_SIZE,
            adaptive_multiplier=self.ADAPTIVE_MULTIPLIER,
            adaptive_min_samples=self.ADAPTIVE_MIN_SAMPLES,
            whitelist_macs=self.WHITELIST_MACS,
            whitelist_ethertypes=self.WHITELIST_ETHERTYPES,
        )
        self.enforcement_module = EnforcementModule(self, self.policy_module)

        # Avvia i moduli
        self.monitoring_module.start()
        self.policy_module.start()
        self.enforcement_module.start()
        
        print("Moduli avviati")
        
        # Avvia l'API REST in un thread daemon
        self.api_thread = threading.Thread(target=self.start_rest_api, daemon=True)
        self.api_thread.start()
        print("API REST avviata")

    def start_rest_api(self):
        app = Flask(__name__)

        def serialize_blocklist(blocklist):
            #Converte la blocklist con timestamp in formato JSON-friendly
            now = time.time()
            return {
                str(key): {
                    'expire_ts': expire_ts,
                    'seconds_remaining': max(0, expire_ts - now),
                    'expired': expire_ts <= now
                }
                for key, expire_ts in blocklist.items()
            }

        @app.route('/api/blocklist', methods=['GET'])
        def get_blocklist():
            #Visualizza tutti i flow attualmente bloccati
            blocklist = self.enforcement_module.get_blocklist()
            return jsonify({
                'status': 'success',
                'blocklist': serialize_blocklist(blocklist),
                'count': len(blocklist),
                'timestamp': time.time()
            }), 200

        @app.route('/api/blocklist', methods=['POST'])
        def add_to_blocklist():
            # aggiunge un flow alla blocklist
            try:
                data = request.get_json(silent=True)
                if not data or 'flow_key' not in data:
                    return jsonify({'error': 'Missing flow_key'}), 400

                flow_key = tuple(data['flow_key']) #qui converte la lista JSON flow_key in una tupla Python, che è il formato utilizzato internamente per rappresentare le chiavi dei flussi. La tupla contiene (dpid, in_port, src_mac, dst_mac, eth_type).
                duration = data.get('duration', SimpleSwitch13.FLOW_BLOCK_SECONDS) #qui imposta la durata del blocco del flusso. Se il client non specifica una durata, viene utilizzata la durata predefinita definita nella classe SimpleSwitch13 (FLOW_BLOCK_SECONDS).

                if not isinstance(duration, (int, float)) or duration <= 0:
                    return jsonify({'error': 'duration must be positive'}), 400

                result = self.enforcement_module.add_to_blocklist(flow_key, duration)
                
                return jsonify({
                    'status': 'success',
                    'message': 'Flow added to blocklist',
                    'flow_key': str(flow_key),
                    'block_duration_sec': duration,
                    'expire_ts': result['expire_ts']
                }), 201
                
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        @app.route('/api/blocklist/<path:flow_key>', methods=['DELETE'])
        def remove_from_blocklist(flow_key):
            #Rimuove uno specifico flow dalla blocklist
            try:
                flow_key_tuple = literal_eval(flow_key) #
                result = self.enforcement_module.remove_from_blocklist(flow_key_tuple)
                status_code = 200 if result['status'] == 'removed' else 404
                return jsonify({
                    'status': 'success',
                    'message': f"Flow {result['status']}",
                    'flow_key': flow_key
                }), status_code
            except Exception as e:
                return jsonify({'error': f'Invalid flow_key: {str(e)}'}), 400

        @app.route('/api/blocklist/info', methods=['GET'])
        def blocklist_info():
            #Statistiche sulla blocklist
            blocklist = self.enforcement_module.get_blocklist()
            now = time.time()

            expired_count = sum(1 for ts in blocklist.values() if ts <= now)
            active_count = len(blocklist) - expired_count #calcola quantità di flussi attivi sottraendo il numero di flussi scaduti dal numero totale di flussi nella blocklist.
            
            return jsonify({
                'status': 'success',
                'total_blocked_flows': len(blocklist),
                'active_blocked_flows': active_count,
                'expired_blocked_flows': expired_count,
                'default_block_duration_sec': self.FLOW_BLOCK_SECONDS,
                'timestamp': now
            }), 200

        
        app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)


    def flow_key(self, dpid, in_port, src, dst, eth_type):
        #crea una tupla chiave per identificare univocamente un flusso.
        return (dpid, in_port, src, dst, eth_type)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER) 
    def flow_stats_reply_handler(self, ev): #ev è l'evento che contiene le statistiche dei flussi ricevute dallo switch. Questo metodo viene chiamato quando il controller riceve una risposta alle richieste di statistiche dei flussi inviate agli switch.
        
        #Gestisce le risposte OpenFlow FlowStats
        #Delega al MonitoringModule per l'estrazione dei dati statistici
        msg = ev.msg
        datapath = msg.datapath
        
        # Il MonitoringModule processa i dati e consegna gli eventi al PolicyModule tramite una coda
        self.monitoring_module.process_flow_stats_reply(datapath, msg.body) #body contiene le statistiche dei flussi ricevute dallo switch. Il MonitoringModule elabora queste statistiche, calcola le metriche necessarie (come il rate di pacchetti) e invia gli eventi al PolicyModule per ulteriori decisioni.

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        #Gestisce la registrazione di un nuovo switch e installa la regola table-miss
        datapath = ev.msg.datapath #datapath rappresenta lo switch che ha inviato l'evento di registrazione. Contiene informazioni sullo switch, come il suo identificatore (dpid) e le capacità supportate.
        ofproto = datapath.ofproto #ofproto è un riferimento alla libreria di protocolli OpenFlow specifica per la versione 1.3. Contiene costanti e metodi utili per costruire messaggi OpenFlow, come le azioni, i tipi di messaggi e le porte speciali.
        parser = datapath.ofproto_parser#il parser è un oggetto che fornisce metodi per creare messaggi OpenFlow specifici per la versione 1.3. Viene utilizzato per costruire messaggi come FlowMod, PacketOut e altri, che vengono inviati allo switch per configurare il comportamento della rete.

        # Installa la regola di table-miss (priorita' minima)
        match = parser.OFPMatch() #qui viene creato un oggetto match vuoto, che corrisponde a tutti i pacchetti. In altre parole, questa regola catturerà qualsiasi pacchetto che non corrisponde a nessuna delle regole specifiche installate successivamente.
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, #OFPP_CONTROLLER indica che i pacchetti che corrispondono a questa regola devono essere inviati al controller. ofproto.OFPCML_NO_BUFFER indica che il pacchetto non deve essere bufferizzato nello switch, ma deve essere inviato interamente al controller.
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        # Registra e rimuove i datapath connessi: serve al MonitoringModule per fare polling.
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info(f"Register datapath dpid={datapath.id}")
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info(f"Unregister datapath dpid={datapath.id}")
                del self.datapaths[datapath.id]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        #costruisce e invia un FlowMod allo switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        #Gestisce i pacchetti ricevuti dal controller (PacketIn)
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data) #pkt è un oggetto che rappresenta il pacchetto ricevuto dal controller. Viene creato a partire dai dati grezzi del pacchetto (msg.data) e consente di analizzare i protocolli incapsulati nel pacchetto, come Ethernet, IP, TCP, ecc.
        eth = pkt.get_protocols(ethernet.ethernet)[0] #eth è un oggetto che rappresenta il protocollo Ethernet incapsulato nel pacchetto. Viene estratto dal pacchetto usando il metodo get_protocols() e specificando il tipo di protocollo desiderato.

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignora LLDP (traffico di controllo/topology discovery)
            return
        
        dst = eth.dst
        src = eth.src
        now_ts = time.time()

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {}) #crea un dizionario vuoto per lo switch se non esiste già, in modo da poter memorizzare le associazioni MAC-to-port per ciascun switch. se esiste

        flow_key = self.flow_key(dpid, in_port, src, dst, eth.ethertype)

        # Verifica se il flow è nella blocklist
        if self.enforcement_module.is_flow_blocked(flow_key, now_ts):
            print(f"drop blocked flow dpid={dpid} in_port={in_port} src={src} dst={dst} eth={eth.ethertype}")
            return

        print(f"packet in {dpid} {src} {dst} {in_port}")

        # associa MAC sorgente alla porta d'ingresso
        self.mac_to_port[dpid][src] = in_port

        # Se la destinazione è nota, inoltra sulla porta specifica; altrimenti usa flood, perchè
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)] #crea un'azione di output per inviare il pacchetto sulla porta specifica

        # Se non stiamo floodando, installa una flow per i prossimi pacchetti simili
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch( #il match viene creato per corrispondere ai pacchetti futuri con le stesse caratteristiche (dpid, in_port, src, dst, eth_type). In questo modo, i pacchetti successivi che corrispondono a questo match verranno gestiti dallo switch senza dover passare nuovamente al controller.
                in_port=in_port,
                eth_dst=dst,
                eth_src=src,
                eth_type=eth.ethertype,
            )
            if msg.buffer_id != ofproto.OFP_NO_BUFFER: #se il pacchetto è stato bufferizzato, ovvero è stato memorizzato temporaneamente nello switch, allora il controller può installare la flow direttamente utilizzando l'ID del buffer. In questo modo, lo switch può inoltrare il pacchetto senza doverlo inviare nuovamente al controller.
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions) #actions è la lista di azioni da eseguire per i pacchetti futuri che corrispondono al match. In questo caso, l'azione è inoltrare il pacchetto sulla porta specificata (out_port).
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Inoltra il pacchetto corrente secondo l'azione scelta
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
