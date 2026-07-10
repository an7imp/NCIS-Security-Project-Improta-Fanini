
import time
import threading
from collections import defaultdict, deque
from statistics import mean
from ryu.lib import hub
from queue import Queue, Empty


class PolicyModule:

    def __init__(
        self,
        controller_app,
        monitoring_module,
        flow_window_sec=1.0,
        flow_pkt_threshold=100,
        flow_block_seconds=15,
        adaptive_threshold_enabled=True,
        adaptive_history_size=12,
        adaptive_multiplier=1.25,
        adaptive_min_samples=3,
        whitelist_macs=None,
        whitelist_ethertypes=None,
    ):
       
        self.controller = controller_app
        self.monitoring_module = monitoring_module

        # Parametri 
        self.flow_window_sec = flow_window_sec
        self.flow_pkt_threshold = flow_pkt_threshold
        self.flow_block_seconds = flow_block_seconds
        self.adaptive_threshold_enabled = adaptive_threshold_enabled
        self.adaptive_history_size = adaptive_history_size
        self.adaptive_multiplier = adaptive_multiplier
        self.adaptive_min_samples = adaptive_min_samples
        self.whitelist_macs = whitelist_macs or set()
        self.whitelist_ethertypes = whitelist_ethertypes or set()

        # Coda di input dal Monitoring Module
        self.stats_queue = monitoring_module.stats_queue

        # Coda di output verso l'Enforcement Module
        self.decisions_queue = Queue()

        # Flussi bloccati recenti per evitare duplicati
        self.recently_blocked = {}  # flow_key -> timestamp
        self.recently_blocked_lock = threading.Lock()

        # Storico pps per flusso per calcolare soglie dinamiche
        self.flow_pps_history = defaultdict(lambda: deque(maxlen=self.adaptive_history_size))
        self.flow_pps_history_lock = threading.Lock()

        # Thread di elaborazione policy
        self.policy_thread = None

    def start(self):
        if self.policy_thread is None:
            self.policy_thread = hub.spawn(self.policy_loop)

    def policy_loop(self):
        while True:
            try:
                # Prendi il prossimo evento dal monitoring
                try:
                    flow_event = self.stats_queue.get(timeout=0.5)
                except Empty:
                    hub.sleep(0.1)
                    continue

                # Applica la logica di policy
                decision = self.evaluate_flow(flow_event)

                # Se la policy decide di bloccare, consegna la decisione
                if decision is not None:
                    self.decisions_queue.put(decision)

            except Exception as e:
                self.controller.logger.error(f"PolicyModule error: {e}")
                hub.sleep(0.1)

    def is_whitelisted(self, src, dst, eth_type):
        return (
            eth_type in self.whitelist_ethertypes
            or src in self.whitelist_macs
            or dst in self.whitelist_macs
        )

    def is_recently_blocked(self, flow_key, now_ts):
        #Verifica se il flusso è stato bloccato di recente per evitare regole duplicate
        with self.recently_blocked_lock:
            last_blocked_ts = self.recently_blocked.get(flow_key)
            if last_blocked_ts is None:
                return False
            # Se è passato meno di 1 secondo, considera ancora bloccato di recente
            if now_ts - last_blocked_ts < 1.0:
                return True

            del self.recently_blocked[flow_key]
            return False

    def mark_as_blocked_recently(self, flow_key, now_ts):
        with self.recently_blocked_lock:
            self.recently_blocked[flow_key] = now_ts

    def get_adaptive_threshold_pps(self, flow_key, src=None, dst=None):
        #Calcola la threshold dinamica per il flusso usando lo storico recente
        static_floor_pps = self.flow_pkt_threshold / self.flow_window_sec

        if not self.adaptive_threshold_enabled:
            return static_floor_pps

        with self.flow_pps_history_lock:
            history = list(self.flow_pps_history.get(flow_key, ()))

        if len(history) < self.adaptive_min_samples:
            print("static floor")
            return static_floor_pps

        baseline_pps = mean(history)
        threshold_pps = baseline_pps * self.adaptive_multiplier


        return max(static_floor_pps, threshold_pps)

    def record_flow_sample(self, flow_key, pps):
        #Aggiunge un sample di pps nello storico
        with self.flow_pps_history_lock:
            self.flow_pps_history[flow_key].append(pps)

    def evaluate_flow(self, flow_event):
        #Applica la logica di policy per decidere se bloccare un flusso.
        #flow_event: Dict con i dati del flusso dal MonitoringModule
        #Ritorna Dict con la decisione di blocco, oppure None se non si blocca

        flow_key = flow_event['flow_key']
        src = flow_event['src']
        dst = flow_event['dst']
        eth_type = flow_event['eth_type']
        pps = flow_event['pps']
        now_ts = flow_event['timestamp']

        # Registra il campione per popolare lo storico
        self.record_flow_sample(flow_key, pps)

        # Calcola la soglia adattiva per il flusso
        threshold_pps = self.get_adaptive_threshold_pps(flow_key, src, dst)

        #Verifica whitelist
        if self.is_whitelisted(src, dst, eth_type):
            return None

        #Verifica se già bloccato di recente
        if self.is_recently_blocked(flow_key, now_ts):
            return None

        #Verifica se supera la threshold
        if pps <= threshold_pps:
            return None

        # Decisione: BLOCCARE il flusso
        decision = {
            'action': 'block',
            'flow_key': flow_key,
            'datapath': flow_event['datapath'],
            'in_port': flow_event['in_port'],
            'src': src,
            'dst': dst,
            'eth_type': eth_type,
            'pps': pps,
            'threshold_pps': threshold_pps,
            'block_duration_sec': self.flow_block_seconds,
            'timestamp': now_ts,
        }

        # Marca il flusso come bloccato di recente
        self.mark_as_blocked_recently(flow_key, now_ts)

        self.controller.logger.info(
            f"PolicyModule DECISION: Block flow {flow_key} "
            f"(pps={pps:.2f} > adaptive_threshold={threshold_pps:.2f})"
        )

        return decision

    def get_decisions_queue(self):
        #Restituisce la coda di decisioni per l'Enforcement Module
        return self.decisions_queue
