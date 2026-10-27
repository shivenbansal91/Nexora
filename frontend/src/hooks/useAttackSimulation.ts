import { useState, useCallback, useRef, useEffect } from 'react';
import { generateAttack, type GraphNodeDef, type AttackEvent, type ThreatInfo } from '../engine/attackEngine';

export type SimPhase = 'idle' | 'detecting' | 'correlating' | 'escalating' | 'resolved';

export interface SimulationState {
  phase: SimPhase;
  /** All nodes that should appear in the graph (attack chain nodes, ordered) */
  chainNodes: GraphNodeDef[];
  /** Number of chain edges to show (reveals progressively) */
  revealedEdgeCount: number;
  /** IDs of nodes that are currently active (suspicious/threat) */
  activeNodeIds: ReadonlySet<string>;
  /** The terminal node of the chain (gets threat styling) */
  threatNodeId: string | null;
  /** Threat panel data */
  threatInfo: ThreatInfo | null;
  /** Events for the live stream */
  liveEvents: AttackEvent[];
  /** Incremental stat deltas since simulation started */
  statsDeltas: { events: number; anomalies: number; threats: number };
  /** Human-readable scenario name */
  scenarioName: string | null;
}

const INITIAL_STATE: SimulationState = {
  phase: 'idle',
  chainNodes: [],
  revealedEdgeCount: 0,
  activeNodeIds: new Set<string>(),
  threatNodeId: null,
  threatInfo: null,
  liveEvents: [],
  statsDeltas: { events: 0, anomalies: 0, threats: 0 },
  scenarioName: null,
};

export function useAttackSimulation() {
  const [state, setState] = useState<SimulationState>(INITIAL_STATE);
  const timersRef  = useRef<ReturnType<typeof setTimeout>[]>([]);
  const isRunning  = useRef(false);

  const clearTimers = () => {
    timersRef.current.forEach(id => clearTimeout(id));
    timersRef.current = [];
  };

  const injectAttack = useCallback(() => {
    if (isRunning.current) return;
    isRunning.current = true;
    clearTimers();

    const attack = generateAttack();
    const { chainNodes, chainEdges, events, threat, scenarioName } = attack;

    // ─ Phase 0 (immediate): Detection starts, first node activates ─
    setState(prev => ({
      ...prev,
      phase: 'detecting',
      chainNodes,
      revealedEdgeCount: 0,
      activeNodeIds: new Set([chainNodes[0].id]),
      threatNodeId: null,
      threatInfo: null,
      scenarioName,
      statsDeltas: { events: prev.statsDeltas.events + 1, anomalies: prev.statsDeltas.anomalies, threats: prev.statsDeltas.threats },
    }));

    // ─ Progressive event + graph reveal ─
    events.forEach((event, i) => {
      const t = setTimeout(() => {
        setState(prev => {
          const isLastEvent = i === events.length - 1;
          
          // Reveal chain progressively as events arrive
          const revealedEdgeCount = Math.min(i + 1, chainEdges.length);
          const activeIds = new Set<string>();
          for (let j = 0; j <= revealedEdgeCount && j < chainNodes.length; j++) {
            activeIds.add(chainNodes[j].id);
          }

          const newEvents: AttackEvent[] = [event, ...prev.liveEvents].slice(0, 25);

          const phase: SimPhase = isLastEvent ? 'resolved'
            : i >= events.length - 2 ? 'escalating'
            : i >= 1 ? 'correlating'
            : 'detecting';

          return {
            ...prev,
            phase,
            revealedEdgeCount,
            activeNodeIds: activeIds,
            threatNodeId: isLastEvent ? chainNodes[chainNodes.length - 1].id : prev.threatNodeId,
            threatInfo: isLastEvent ? threat : prev.threatInfo,
            liveEvents: newEvents,
            statsDeltas: {
              events:    prev.statsDeltas.events + 1,
              anomalies: event.severity === 'high'     ? prev.statsDeltas.anomalies + 1 : prev.statsDeltas.anomalies,
              threats:   event.severity === 'critical' ? Math.max(prev.statsDeltas.threats, 1) : prev.statsDeltas.threats,
            },
          };
        });
      }, event.delayMs);

      timersRef.current.push(t);
    });

    // Mark done
    const doneDelay = (events[events.length - 1]?.delayMs ?? 5000) + 600;
    const doneT = setTimeout(() => {
      isRunning.current = false;
    }, doneDelay);
    timersRef.current.push(doneT);

  }, []);

  // Cleanup on unmount
  useEffect(() => () => clearTimers(), []);

  return { state, injectAttack };
}
