

import time
import threading
from ryu.lib import hub
from queue import Empty


class EnforcementModule:


    def __init__(self, controller_app, policy_module):
       
        self.controller = controller_app
        self.policy_module = policy_module

        # Coda di input dal Policy Module
        self.decisions_queue = policy_module.get_decisions_queue()

        # Blocklist condivisa globale: flow_key -> expire_ts
        self.shared_blocklist = {}
        self.blocklist_lock = threading.Lock()

        # Thread di esecuzione
        self.enforcement_thread = None

    def start(self):
        #Thread
        if self.enforcement_thread is None:
            self.enforcement_thread = hub.spawn(self.enforcement_loop)


    def enforcement_loop(self):
        while True:
            try:
                # Prendi la prossima decisione (non-blocking)
                try:
                    decision = self.decisions_queue.get(timeout=0.5)
                except Empty:
                    hub.sleep(0.1) #timeout e sleep fanno sì che il thread non rimanga bloccato indefinitamente se non ci sono nuove decisioni da elaborare. in particolare, se non ci sono decisioni nella coda entro 0.5 secondi, solleva un'eccezione Empty e il thread dorme per 0.1 secondi prima di riprovare.
                    continue

                # Applica la decisione
                if decision['action'] == 'block':
                    self.enforce_block(decision)

            except Exception as e:
                self.controller.logger.error(f"EnforcementModule error: {e}")
                hub.sleep(0.1)

    def enforce_block(self, decision):

        #installa regola drop sul switch


        #decision: Dict con i dati della decisione dal PolicyModule
        
        flow_key = decision['flow_key']
        datapath = decision['datapath']
        in_port = decision['in_port']
        src = decision['src']
        dst = decision['dst']
        eth_type = decision['eth_type']
        block_duration_sec = decision['block_duration_sec']
        pps = decision['pps']
        now_ts = decision['timestamp']

        #Aggiunge alla blocklist condivisa
        with self.blocklist_lock:
            expire_ts = now_ts + block_duration_sec
            self.shared_blocklist[flow_key] = expire_ts

        #Installa la regola drop sul switch
        try:
            parser = datapath.ofproto_parser
            drop_match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst,
                eth_type=eth_type,
            )
            self.install_drop_flow(datapath, drop_match, block_duration_sec)

            self.controller.logger.warning(
                f"EnforcementModule: BLOCKED flow {flow_key} "
                f"for {block_duration_sec}s (pps={pps:.2f}) "
                f"dpid={datapath.id} in_port={in_port} "
                f"src={src} dst={dst} eth_type={eth_type}"
            )
        except Exception as e:
            self.controller.logger.error(
                f"EnforcementModule: Failed to install drop rule for {flow_key}: {e}"
            )

    def install_drop_flow(self, datapath, match, hard_timeout):
        
        parser = datapath.ofproto_parser #parser è un oggetto che fornisce metodi per creare oggetti OpenFlow in modo compatibile con la versione dello switch.
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=[],  # Nessuna azione = drop
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    def is_flow_blocked(self, flow_key, now_ts=None):
       
        #Verifica se un flusso è nella blocklist e non è scaduto
        #Utilizzato durante PacketIn.

        if now_ts is None:
            now_ts = time.time()

        with self.blocklist_lock:
            expire_ts = self.shared_blocklist.get(flow_key)
            if expire_ts is None or now_ts >= expire_ts:
                # Il blocco è scaduto oppure non esiste più: rimuovi in modo sicuro.
                self.shared_blocklist.pop(flow_key, None)
                return False

        return True
    
    # API per getione blocklist

    def add_to_blocklist(self, flow_key, block_duration_sec=None):
         #Aggiunge manualmente un flusso alla blocklist.
    
        if block_duration_sec is None:
            block_duration_sec = self.policy_module.flow_block_seconds

        with self.blocklist_lock:
            expire_ts = time.time() + block_duration_sec
            self.shared_blocklist[flow_key] = expire_ts

        return {'status': 'added', 'expire_ts': expire_ts}

    def remove_from_blocklist(self, flow_key):
      
        #Rimuove manualmente un flusso dalla blocklist.
      
        with self.blocklist_lock:
            removed = self.shared_blocklist.pop(flow_key, None) is not None

        return {'status': 'removed' if removed else 'not_found'}

    def get_blocklist(self):
        #Restituisce la blocklist attuale
        with self.blocklist_lock:
            return dict(self.shared_blocklist)

    
