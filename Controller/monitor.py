
import time
import threading
from ryu.lib import hub
from queue import Queue


class MonitoringModule:

    def __init__(self, controller_app, stats_poll_interval_sec=1.0):

        self.controller = controller_app
        self.stats_poll_interval = stats_poll_interval_sec

        # Coda thread-safe per consegnare le statistiche raccolte al Policy Module
        self.stats_queue = Queue()

        
        self.flow_stats_prev = {}  # key -> {'ts': float, 'pkt_count': int}
        self.flow_stats_lock = threading.Lock()

        # Thread 
        self.monitor_thread = None

    def start(self):
        #avvia il thread
        if self.monitor_thread is None:
            self.monitor_thread = hub.spawn(self.monitor_loop)


    def monitor_loop(self):
       #chiede periodicamente stats agli switch e consegna al policy module
        while True:
            try:
                # ottieni lista dei datapath connessi dal controller
                datapaths = list(getattr(self.controller, 'datapaths', {}).values())

                for datapath in datapaths:
                    self.request_flow_stats(datapath)

                hub.sleep(self.stats_poll_interval)
            except Exception as e:
                self.controller.logger.error(f"MonitoringModule error: {e}")
                hub.sleep(self.stats_poll_interval)

    def request_flow_stats(self, datapath):
        #Invia OFPFlowStatsRequest allo switch
        try:
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)
        except Exception as e:
            self.controller.logger.error(f"Failed to request stats from dpid={datapath.id}: {e}")

    def process_flow_stats_reply(self, datapath, flow_stats_body):
        
        #Processa i FlowStatsReply ricevuti dai switch.
        #Calcola rate di pacchetti e consegna al Policy Module



        now_ts = time.time()
        dpid = datapath.id

        with self.flow_stats_lock:
            for stat in flow_stats_body:
                # Considera solo le flow di forwarding apprese (priority=1)
                if stat.priority != 1:
                    continue

                in_port = stat.match.get('in_port')
                src = stat.match.get('eth_src')
                dst = stat.match.get('eth_dst')
                eth_type = stat.match.get('eth_type')

                # Se il match non contiene i campi attesi salta
                if None in (in_port, src, dst, eth_type):
                    continue

                flow_key = (dpid, in_port, src, dst, eth_type)

                prev = self.flow_stats_prev.get(flow_key)
                self.flow_stats_prev[flow_key] = {'ts': now_ts, 'pkt_count': stat.packet_count}

                if prev is None:
                    continue

                delta_t = now_ts - prev['ts']
                if delta_t <= 0:
                    continue

                delta_pkts = stat.packet_count - prev['pkt_count']
                if delta_pkts < 0:
                    # Counter reset (riavvio switch o flow ricreata)
                    continue

                pps = delta_pkts / delta_t

                # Crea un evento di statistica con tutti i dati rilevanti
                flow_event = {
                    'flow_key': flow_key,
                    'datapath': datapath,
                    'in_port': in_port,
                    'src': src,
                    'dst': dst,
                    'eth_type': eth_type,
                    'pps': pps,
                    'packet_count': stat.packet_count,
                    'byte_count': stat.byte_count,
                    'duration_sec': stat.duration_sec,
                    'timestamp': now_ts,
                }

                # Consegna il flusso al Policy Module
                self.stats_queue.put(flow_event)

