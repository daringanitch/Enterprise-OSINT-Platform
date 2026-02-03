#!/usr/bin/env python3
"""
Graph Influence Propagation Algorithms

Model how threats, malware, or information spreads through a network.
Essential for threat intelligence to predict attack paths, assess
blast radius, and identify critical chokepoints.

Capabilities:
- Independent Cascade Model (probabilistic spread)
- Linear Threshold Model (threshold-based activation)
- SIR/SIS Epidemic Models (infection dynamics)
- Influence Maximization (find best seed nodes)
- Blast Radius Analysis (impact assessment)
"""

import logging
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import (
    ExtendedEntityType,
    ExtendedRelationshipType,
    GraphNode,
    GraphEdge,
)

logger = logging.getLogger(__name__)


# =============================================================================
# RESULT CLASSES
# =============================================================================

@dataclass
class PropagationStep:
    """Single step in the propagation process."""
    step: int
    newly_activated: List[str]
    total_activated: int
    activation_paths: Dict[str, str] = field(default_factory=dict)  # node -> activated_by

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "newly_activated": self.newly_activated,
            "newly_activated_count": len(self.newly_activated),
            "total_activated": self.total_activated,
        }


@dataclass
class PropagationResult:
    """Result of influence propagation simulation."""
    model: str
    seed_nodes: List[str]
    final_activated: List[str]
    total_reach: int
    reach_percentage: float
    steps: List[PropagationStep] = field(default_factory=list)
    activation_tree: Dict[str, str] = field(default_factory=dict)  # node -> activated_by
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "seed_nodes": self.seed_nodes,
            "total_reach": self.total_reach,
            "reach_percentage": round(self.reach_percentage, 4),
            "final_activated_count": len(self.final_activated),
            "final_activated": self.final_activated[:100],  # Limit output
            "propagation_steps": len(self.steps),
            "steps": [s.to_dict() for s in self.steps],
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


@dataclass
class BlastRadiusResult:
    """Result of blast radius analysis."""
    source_entity: str
    direct_impact: List[str]
    indirect_impact: List[str]
    total_impact: int
    impact_by_hop: Dict[int, List[str]] = field(default_factory=dict)
    impact_by_type: Dict[str, int] = field(default_factory=dict)
    critical_paths: List[List[str]] = field(default_factory=list)
    risk_score: float = 0.0
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_entity": self.source_entity,
            "direct_impact_count": len(self.direct_impact),
            "indirect_impact_count": len(self.indirect_impact),
            "total_impact": self.total_impact,
            "impact_by_hop": {k: len(v) for k, v in self.impact_by_hop.items()},
            "impact_by_type": self.impact_by_type,
            "risk_score": round(self.risk_score, 4),
            "critical_paths": self.critical_paths[:10],
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


@dataclass
class InfluenceMaxResult:
    """Result of influence maximization."""
    k: int
    seed_set: List[str]
    expected_reach: float
    reach_percentage: float
    marginal_gains: List[Tuple[str, float]] = field(default_factory=list)
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "k": self.k,
            "seed_set": self.seed_set,
            "expected_reach": round(self.expected_reach, 2),
            "reach_percentage": round(self.reach_percentage, 4),
            "marginal_gains": [(n, round(g, 2)) for n, g in self.marginal_gains],
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


@dataclass
class EpidemicResult:
    """Result of epidemic simulation."""
    model: str  # "SIR" or "SIS"
    initial_infected: List[str]
    peak_infected: int
    peak_step: int
    final_state: Dict[str, str]  # node -> state (S/I/R)
    state_history: List[Dict[str, int]] = field(default_factory=list)
    r0_estimate: float = 0.0  # Basic reproduction number
    computation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        state_counts = defaultdict(int)
        for state in self.final_state.values():
            state_counts[state] += 1

        return {
            "model": self.model,
            "initial_infected": self.initial_infected,
            "peak_infected": self.peak_infected,
            "peak_step": self.peak_step,
            "final_susceptible": state_counts.get("S", 0),
            "final_infected": state_counts.get("I", 0),
            "final_recovered": state_counts.get("R", 0),
            "r0_estimate": round(self.r0_estimate, 2),
            "total_steps": len(self.state_history),
            "computation_time_ms": round(self.computation_time_ms, 2),
        }


# =============================================================================
# INFLUENCE ENGINE
# =============================================================================

class InfluenceEngine:
    """
    Engine for simulating influence propagation through the graph.

    Models supported:
    - Independent Cascade (IC): Probabilistic spread based on edge weights
    - Linear Threshold (LT): Threshold-based activation
    - SIR: Susceptible-Infected-Recovered epidemic
    - SIS: Susceptible-Infected-Susceptible epidemic
    """

    def __init__(self, client=None):
        """
        Initialize the influence engine.

        Args:
            client: Optional GraphClient for database access
        """
        self.client = client

        # Internal graph representation
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[str, Set[str]] = {}
        self._in_adjacency: Dict[str, Set[str]] = {}
        self._edge_weights: Dict[Tuple[str, str], float] = {}

    # =========================================================================
    # GRAPH BUILDING
    # =========================================================================

    def build_graph(
        self,
        nodes: List[GraphNode],
        edges: List[GraphEdge]
    ) -> None:
        """
        Build internal graph representation.

        Args:
            nodes: List of GraphNode objects
            edges: List of GraphEdge objects
        """
        self._nodes = {n.entity_id: n for n in nodes}
        self._edges = edges
        self._adjacency = {n.entity_id: set() for n in nodes}
        self._in_adjacency = {n.entity_id: set() for n in nodes}
        self._edge_weights = {}

        for edge in edges:
            if edge.source_id in self._adjacency and edge.target_id in self._nodes:
                # Directed edges (source activates target)
                self._adjacency[edge.source_id].add(edge.target_id)
                self._in_adjacency[edge.target_id].add(edge.source_id)

                # Store edge weight as propagation probability
                self._edge_weights[(edge.source_id, edge.target_id)] = edge.composite_weight

        logger.info(f"Built influence graph with {len(self._nodes)} nodes, "
                   f"{len(self._edges)} edges")

    # =========================================================================
    # INDEPENDENT CASCADE MODEL
    # =========================================================================

    def independent_cascade(
        self,
        seed_nodes: List[str],
        max_steps: int = 100,
        probability_scale: float = 1.0,
        seed: int = None
    ) -> PropagationResult:
        """
        Simulate Independent Cascade propagation.

        Each active node has one chance to activate each inactive neighbor
        with probability equal to the edge weight.

        Args:
            seed_nodes: Initial infected/active nodes
            max_steps: Maximum simulation steps
            probability_scale: Scale factor for propagation probabilities
            seed: Random seed for reproducibility

        Returns:
            PropagationResult with propagation details
        """
        start_time = time.time()

        if seed is not None:
            random.seed(seed)

        # Initialize
        active = set(seed_nodes) & set(self._nodes.keys())
        newly_active = set(active)
        activation_tree = {n: "seed" for n in active}
        steps = []

        step = 0
        while newly_active and step < max_steps:
            step += 1
            next_active = set()

            for node in newly_active:
                # Try to activate each neighbor
                for neighbor in self._adjacency.get(node, set()):
                    if neighbor not in active:
                        prob = self._edge_weights.get((node, neighbor), 0.5)
                        prob *= probability_scale

                        if random.random() < prob:
                            next_active.add(neighbor)
                            if neighbor not in activation_tree:
                                activation_tree[neighbor] = node

            # Record step
            steps.append(PropagationStep(
                step=step,
                newly_activated=list(next_active),
                total_activated=len(active) + len(next_active),
                activation_paths={n: activation_tree.get(n, "") for n in next_active},
            ))

            active.update(next_active)
            newly_active = next_active

        computation_time = (time.time() - start_time) * 1000

        return PropagationResult(
            model="independent_cascade",
            seed_nodes=list(seed_nodes),
            final_activated=list(active),
            total_reach=len(active),
            reach_percentage=len(active) / len(self._nodes) if self._nodes else 0,
            steps=steps,
            activation_tree=activation_tree,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # LINEAR THRESHOLD MODEL
    # =========================================================================

    def linear_threshold(
        self,
        seed_nodes: List[str],
        max_steps: int = 100,
        threshold: float = 0.5,
        seed: int = None
    ) -> PropagationResult:
        """
        Simulate Linear Threshold propagation.

        A node activates when the weighted sum of active neighbors
        exceeds its threshold.

        Args:
            seed_nodes: Initial active nodes
            max_steps: Maximum simulation steps
            threshold: Activation threshold (or "random" for random thresholds)
            seed: Random seed for reproducibility

        Returns:
            PropagationResult with propagation details
        """
        start_time = time.time()

        if seed is not None:
            random.seed(seed)

        # Initialize
        active = set(seed_nodes) & set(self._nodes.keys())
        activation_tree = {n: "seed" for n in active}
        steps = []

        # Assign random thresholds to nodes
        thresholds = {}
        for node in self._nodes:
            if isinstance(threshold, (int, float)):
                thresholds[node] = threshold
            else:
                thresholds[node] = random.random()

        step = 0
        changed = True

        while changed and step < max_steps:
            step += 1
            changed = False
            newly_active = []

            for node in self._nodes:
                if node in active:
                    continue

                # Calculate influence from active neighbors
                in_neighbors = self._in_adjacency.get(node, set())
                active_neighbors = in_neighbors & active

                if not active_neighbors:
                    continue

                # Weighted sum of influence
                total_influence = sum(
                    self._edge_weights.get((n, node), 0.5)
                    for n in active_neighbors
                )

                # Normalize by total possible influence
                max_influence = sum(
                    self._edge_weights.get((n, node), 0.5)
                    for n in in_neighbors
                ) or 1

                normalized_influence = total_influence / max_influence

                if normalized_influence >= thresholds[node]:
                    newly_active.append(node)
                    # Find most influential activator
                    best_activator = max(
                        active_neighbors,
                        key=lambda n: self._edge_weights.get((n, node), 0)
                    )
                    activation_tree[node] = best_activator
                    changed = True

            if newly_active:
                steps.append(PropagationStep(
                    step=step,
                    newly_activated=newly_active,
                    total_activated=len(active) + len(newly_active),
                ))
                active.update(newly_active)

        computation_time = (time.time() - start_time) * 1000

        return PropagationResult(
            model="linear_threshold",
            seed_nodes=list(seed_nodes),
            final_activated=list(active),
            total_reach=len(active),
            reach_percentage=len(active) / len(self._nodes) if self._nodes else 0,
            steps=steps,
            activation_tree=activation_tree,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # SIR EPIDEMIC MODEL
    # =========================================================================

    def sir_epidemic(
        self,
        initial_infected: List[str],
        infection_rate: float = 0.3,
        recovery_rate: float = 0.1,
        max_steps: int = 100,
        seed: int = None
    ) -> EpidemicResult:
        """
        Simulate SIR (Susceptible-Infected-Recovered) epidemic.

        Infected nodes can infect susceptible neighbors,
        then recover and become immune.

        Args:
            initial_infected: Initially infected nodes
            infection_rate: Base probability of infection per contact
            recovery_rate: Probability of recovery per step
            max_steps: Maximum simulation steps
            seed: Random seed for reproducibility

        Returns:
            EpidemicResult with epidemic dynamics
        """
        start_time = time.time()

        if seed is not None:
            random.seed(seed)

        # Initialize states: S=Susceptible, I=Infected, R=Recovered
        states = {n: "S" for n in self._nodes}
        for node in initial_infected:
            if node in states:
                states[node] = "I"

        state_history = []
        peak_infected = len([s for s in states.values() if s == "I"])
        peak_step = 0
        total_infected_ever = set(initial_infected) & set(self._nodes.keys())

        for step in range(max_steps):
            # Count current states
            counts = {"S": 0, "I": 0, "R": 0}
            for state in states.values():
                counts[state] += 1

            state_history.append(counts.copy())

            if counts["I"] > peak_infected:
                peak_infected = counts["I"]
                peak_step = step

            if counts["I"] == 0:
                break

            # Process infections and recoveries
            new_states = states.copy()

            for node, state in states.items():
                if state == "I":
                    # Try to infect neighbors
                    for neighbor in self._adjacency.get(node, set()):
                        if states[neighbor] == "S":
                            edge_weight = self._edge_weights.get((node, neighbor), 0.5)
                            prob = infection_rate * edge_weight
                            if random.random() < prob:
                                new_states[neighbor] = "I"
                                total_infected_ever.add(neighbor)

                    # Try to recover
                    if random.random() < recovery_rate:
                        new_states[node] = "R"

            states = new_states

        # Estimate R0 (basic reproduction number)
        if len(total_infected_ever) > len(initial_infected):
            r0 = (len(total_infected_ever) - len(initial_infected)) / max(len(initial_infected), 1)
        else:
            r0 = 0

        computation_time = (time.time() - start_time) * 1000

        return EpidemicResult(
            model="SIR",
            initial_infected=list(initial_infected),
            peak_infected=peak_infected,
            peak_step=peak_step,
            final_state=states,
            state_history=state_history,
            r0_estimate=r0,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # SIS EPIDEMIC MODEL
    # =========================================================================

    def sis_epidemic(
        self,
        initial_infected: List[str],
        infection_rate: float = 0.3,
        recovery_rate: float = 0.2,
        max_steps: int = 100,
        seed: int = None
    ) -> EpidemicResult:
        """
        Simulate SIS (Susceptible-Infected-Susceptible) epidemic.

        Infected nodes can recover but become susceptible again
        (no immunity). Can reach endemic equilibrium.

        Args:
            initial_infected: Initially infected nodes
            infection_rate: Base probability of infection per contact
            recovery_rate: Probability of recovery per step
            max_steps: Maximum simulation steps
            seed: Random seed for reproducibility

        Returns:
            EpidemicResult with epidemic dynamics
        """
        start_time = time.time()

        if seed is not None:
            random.seed(seed)

        # Initialize states
        states = {n: "S" for n in self._nodes}
        for node in initial_infected:
            if node in states:
                states[node] = "I"

        state_history = []
        peak_infected = len([s for s in states.values() if s == "I"])
        peak_step = 0

        for step in range(max_steps):
            counts = {"S": 0, "I": 0}
            for state in states.values():
                counts[state] += 1

            state_history.append(counts.copy())

            if counts["I"] > peak_infected:
                peak_infected = counts["I"]
                peak_step = step

            if counts["I"] == 0:
                break

            new_states = states.copy()

            for node, state in states.items():
                if state == "I":
                    # Try to infect neighbors
                    for neighbor in self._adjacency.get(node, set()):
                        if states[neighbor] == "S":
                            edge_weight = self._edge_weights.get((node, neighbor), 0.5)
                            prob = infection_rate * edge_weight
                            if random.random() < prob:
                                new_states[neighbor] = "I"

                    # Try to recover (back to susceptible)
                    if random.random() < recovery_rate:
                        new_states[node] = "S"

            states = new_states

        # R0 approximation for SIS
        avg_degree = sum(len(self._adjacency.get(n, set())) for n in self._nodes) / max(len(self._nodes), 1)
        r0 = infection_rate * avg_degree / recovery_rate if recovery_rate > 0 else 0

        computation_time = (time.time() - start_time) * 1000

        return EpidemicResult(
            model="SIS",
            initial_infected=list(initial_infected),
            peak_infected=peak_infected,
            peak_step=peak_step,
            final_state=states,
            state_history=state_history,
            r0_estimate=r0,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # BLAST RADIUS ANALYSIS
    # =========================================================================

    def blast_radius(
        self,
        source_entity: str,
        max_hops: int = 3,
        probability_threshold: float = 0.1
    ) -> BlastRadiusResult:
        """
        Analyze the blast radius of a compromised entity.

        Determines which entities could be impacted if the source
        is compromised, considering propagation probabilities.

        Args:
            source_entity: Starting entity (compromised node)
            max_hops: Maximum propagation distance
            probability_threshold: Minimum cumulative probability to include

        Returns:
            BlastRadiusResult with impact analysis
        """
        start_time = time.time()

        if source_entity not in self._nodes:
            return BlastRadiusResult(
                source_entity=source_entity,
                direct_impact=[],
                indirect_impact=[],
                total_impact=0,
                computation_time_ms=(time.time() - start_time) * 1000,
            )

        # BFS with probability tracking
        visited = {source_entity: 1.0}  # node -> cumulative probability
        impact_by_hop = {0: [source_entity]}
        paths: Dict[str, List[str]] = {source_entity: [source_entity]}

        current_hop = {source_entity}

        for hop in range(1, max_hops + 1):
            next_hop = set()
            impact_by_hop[hop] = []

            for node in current_hop:
                node_prob = visited[node]

                for neighbor in self._adjacency.get(node, set()):
                    edge_prob = self._edge_weights.get((node, neighbor), 0.5)
                    cumulative_prob = node_prob * edge_prob

                    if cumulative_prob >= probability_threshold:
                        if neighbor not in visited or cumulative_prob > visited[neighbor]:
                            visited[neighbor] = cumulative_prob
                            paths[neighbor] = paths[node] + [neighbor]

                            if neighbor not in current_hop:
                                next_hop.add(neighbor)
                                impact_by_hop[hop].append(neighbor)

            current_hop = next_hop

        # Classify impact
        direct_impact = impact_by_hop.get(1, [])
        indirect_impact = []
        for hop in range(2, max_hops + 1):
            indirect_impact.extend(impact_by_hop.get(hop, []))

        # Count by entity type
        impact_by_type: Dict[str, int] = defaultdict(int)
        for node_id in visited:
            if node_id != source_entity:
                node = self._nodes.get(node_id)
                if node:
                    impact_by_type[node.entity_type.value] += 1

        # Find critical paths (high-impact routes)
        critical_paths = []
        for node_id, path in paths.items():
            if len(path) > 1 and visited.get(node_id, 0) > 0.5:
                critical_paths.append(path)

        critical_paths.sort(key=len, reverse=True)

        # Calculate overall risk score
        total_risk = sum(visited.values()) - 1  # Exclude source
        max_possible_risk = len(self._nodes) - 1
        risk_score = total_risk / max_possible_risk if max_possible_risk > 0 else 0

        computation_time = (time.time() - start_time) * 1000

        return BlastRadiusResult(
            source_entity=source_entity,
            direct_impact=direct_impact,
            indirect_impact=indirect_impact,
            total_impact=len(visited) - 1,
            impact_by_hop=impact_by_hop,
            impact_by_type=dict(impact_by_type),
            critical_paths=critical_paths[:10],
            risk_score=risk_score,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # INFLUENCE MAXIMIZATION
    # =========================================================================

    def influence_maximization(
        self,
        k: int,
        model: str = "independent_cascade",
        simulations: int = 100,
        seed: int = None
    ) -> InfluenceMaxResult:
        """
        Find the k most influential seed nodes (greedy algorithm).

        Uses Monte Carlo simulation to estimate influence spread.

        Args:
            k: Number of seed nodes to select
            model: Propagation model ("independent_cascade" or "linear_threshold")
            simulations: Number of simulations for estimation
            seed: Random seed for reproducibility

        Returns:
            InfluenceMaxResult with optimal seed set
        """
        start_time = time.time()

        if seed is not None:
            random.seed(seed)

        seed_set = []
        marginal_gains = []

        for _ in range(k):
            best_node = None
            best_gain = -1

            for candidate in self._nodes:
                if candidate in seed_set:
                    continue

                # Estimate marginal gain
                test_seeds = seed_set + [candidate]
                total_spread = 0

                for _ in range(simulations):
                    if model == "independent_cascade":
                        result = self.independent_cascade(test_seeds, max_steps=50)
                    else:
                        result = self.linear_threshold(test_seeds, max_steps=50)

                    total_spread += result.total_reach

                avg_spread = total_spread / simulations

                # Calculate marginal gain
                if seed_set:
                    current_spread = 0
                    for _ in range(simulations):
                        if model == "independent_cascade":
                            result = self.independent_cascade(seed_set, max_steps=50)
                        else:
                            result = self.linear_threshold(seed_set, max_steps=50)
                        current_spread += result.total_reach
                    current_avg = current_spread / simulations
                    gain = avg_spread - current_avg
                else:
                    gain = avg_spread

                if gain > best_gain:
                    best_gain = gain
                    best_node = candidate

            if best_node:
                seed_set.append(best_node)
                marginal_gains.append((best_node, best_gain))

        # Calculate final expected reach
        final_spread = 0
        for _ in range(simulations):
            if model == "independent_cascade":
                result = self.independent_cascade(seed_set, max_steps=50)
            else:
                result = self.linear_threshold(seed_set, max_steps=50)
            final_spread += result.total_reach

        expected_reach = final_spread / simulations
        reach_percentage = expected_reach / len(self._nodes) if self._nodes else 0

        computation_time = (time.time() - start_time) * 1000

        return InfluenceMaxResult(
            k=k,
            seed_set=seed_set,
            expected_reach=expected_reach,
            reach_percentage=reach_percentage,
            marginal_gains=marginal_gains,
            computation_time_ms=computation_time,
        )

    # =========================================================================
    # PROPERTIES
    # =========================================================================

    @property
    def node_count(self) -> int:
        """Get number of nodes."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Get number of edges."""
        return len(self._edges)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def simulate_propagation(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    seed_nodes: List[str],
    model: str = "independent_cascade",
    **kwargs
) -> PropagationResult:
    """
    Simulate influence propagation.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        seed_nodes: Initial active nodes
        model: Propagation model
        **kwargs: Model-specific parameters

    Returns:
        PropagationResult with propagation details
    """
    engine = InfluenceEngine()
    engine.build_graph(nodes, edges)

    if model == "independent_cascade":
        return engine.independent_cascade(seed_nodes, **kwargs)
    elif model == "linear_threshold":
        return engine.linear_threshold(seed_nodes, **kwargs)
    else:
        raise ValueError(f"Unknown model: {model}")


def analyze_blast_radius(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    source_entity: str,
    max_hops: int = 3
) -> BlastRadiusResult:
    """
    Analyze blast radius of a compromised entity.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        source_entity: Compromised entity
        max_hops: Maximum propagation distance

    Returns:
        BlastRadiusResult with impact analysis
    """
    engine = InfluenceEngine()
    engine.build_graph(nodes, edges)
    return engine.blast_radius(source_entity, max_hops=max_hops)


def find_critical_spreaders(
    nodes: List[GraphNode],
    edges: List[GraphEdge],
    k: int = 5,
    simulations: int = 50
) -> InfluenceMaxResult:
    """
    Find the k most influential entities.

    Args:
        nodes: List of GraphNode objects
        edges: List of GraphEdge objects
        k: Number of entities to find
        simulations: Monte Carlo simulations

    Returns:
        InfluenceMaxResult with top spreaders
    """
    engine = InfluenceEngine()
    engine.build_graph(nodes, edges)
    return engine.influence_maximization(k, simulations=simulations)
