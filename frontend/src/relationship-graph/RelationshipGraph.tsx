// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Bounded one-hop Relationship graph over the canonical PR 31C API (31D).
//
// React Flow (@xyflow/react) renders exactly the bounded
// ``GraphNeighborhoodResponse`` returned by the canonical graph endpoint:
// one server Entity is one node, one server Relationship is one edge, and
// RelationshipObservation summaries are selection metadata, never edges.
// Entity metadata (type/value/display name) comes from GraphNode; the
// ``truncated`` flag drives the bounded notice; node/edge selection,
// pan/zoom/fit and dragging are browser-only presentation state that is
// never persisted or sent to FastAPI. React Flow node/edge IDs such as
// ``n:<uuid>`` / ``e:<uuid>`` are presentation-only wrappers; canonical
// Entity/Relationship IDs remain authoritative. The accessible non-spatial
// alternative (an edge list with exact navigation links) is always
// rendered, so canvas exploration is never required.

import { Alert, Box, Button, Link, Typography } from "@mui/material";
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  useNodesState,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { ReactElement } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";

import { CompactId } from "../components/CompactId";
import { Timestamp } from "../components/Timestamp";
import { DetailRows } from "../analyst-table/DetailRows";
import { PivotMenu, type PivotLocalAction } from "../pivots/PivotMenu";
import { entityActions } from "../pivots/pivot-capabilities";
import { relationshipObservationsAction } from "../pivots/pivot-capabilities";
import type { RelationshipDirectionName } from "../api/schema-types";
import type { RelationshipGraphModel, RelationshipGraphNode } from "./relationship-graph-model";
import {
  layoutSize,
  positionsForExpandedNodes,
  radialPositions,
  type GraphPosition,
} from "./relationship-graph-layout";
import type { GraphExpansionController } from "./use-graph-expansion";

/** One custom React Flow node backed by an exact Entity ID. */
export type EvolutionNodeData = {
  label: string;
  role: "focal" | "counterparty";
  /** Visible entity-type cue (never a color-only differentiation). */
  entityTypeText: string;
} & Record<string, unknown>;

const nodeTypes: NodeTypes = { evolutionNode: EvolutionGraphNode };

function EvolutionGraphNode({ data }: NodeProps): ReactElement {
  const nodeData = data as EvolutionNodeData;
  return (
    <Box
      sx={{
        px: 1.5,
        py: 0.75,
        border: 2,
        borderRadius: 999,
        borderColor: nodeData.role === "focal" ? "primary.main" : "divider",
        bgcolor: nodeData.role === "focal" ? "primary.main" : "background.paper",
        color: nodeData.role === "focal" ? "primary.contrastText" : "text.primary",
        fontSize: 12,
        fontFamily: "monospace",
        whiteSpace: "nowrap",
        maxWidth: 220,
        overflow: "hidden",
        textOverflow: "ellipsis",
      }}
    >
      <Handle type="target" position={Position.Top} />
      {nodeData.label}
      <Box
        component="span"
        aria-label="Entity type"
        sx={{
          display: "block",
          fontSize: 10,
          fontFamily: "sans-serif",
          textTransform: "uppercase",
          letterSpacing: "0.04em",
          opacity: 0.85,
        }}
      >
        {nodeData.entityTypeText}
      </Box>
      <Handle type="source" position={Position.Bottom} />
    </Box>
  );
}

export interface RelationshipGraphProps {
  investigationId: string;
  /** Root graph context key (investigation/focal/direction/type); a change
   * resets the deterministic root layout and dropped expansion state. */
  rootGraphKey: string;
  focalEntityId: string;
  model: RelationshipGraphModel;
  /** Relationship type URN -> analyst label. */
  typeLabel: (type: string) => string;
  /** Entity type -> analyst label (exact text, non-color differentiation). */
  entityTypeLabel: (type: string) => string;
  /** PR 31E analyst-driven expansion controller (owned by the workspace). */
  expansion: GraphExpansionController;
}

/** The bounded accumulated graph surface with an always-available list path. */
export function RelationshipGraph({
  investigationId,
  rootGraphKey,
  focalEntityId,
  model,
  typeLabel,
  entityTypeLabel,
  expansion,
}: RelationshipGraphProps): ReactElement {
  const { t } = useTranslation("relationshipEvolution");
  const [selection, setSelection] = useState<
    { kind: "node"; nodeId: string } | { kind: "edge"; edgeId: string } | null
  >(null);

  const counterpartyIds = useMemo(
    () => model.counterparties.map((node) => node.entityId),
    [model.counterparties],
  );
  const positions = useMemo(
    () => radialPositions(model.focal.entityId, counterpartyIds),
    [model.focal.entityId, counterpartyIds],
  );
  const size = useMemo(() => layoutSize(counterpartyIds.length), [counterpartyIds.length]);

  const initialNodes: Node<EvolutionNodeData>[] = useMemo(
    () => [
      {
        id: nodeId(model.focal.entityId),
        type: "evolutionNode",
        position: positions.focal,
        data: {
          label: model.focal.label,
          role: "focal",
          entityTypeText: entityTypeLabel(model.focal.entityType),
        },
      },
      ...model.counterparties.map((node) => ({
        id: nodeId(node.entityId),
        type: "evolutionNode" as const,
        position: positions.counterparties.get(node.entityId) ?? { x: 0, y: 0 },
        data: {
          label: node.label,
          role: node.role,
          entityTypeText: entityTypeLabel(node.entityType),
        },
      })),
    ],
    [model, positions, entityTypeLabel],
  );

  // Functional dragging: React Flow stays controlled through the standard
  // node-change path. Drag positions are local browser state only; a new
  // root graph context (or a refresh/refetch of that context) resets the
  // deterministic initial layout, and coordinates are never persisted or
  // sent to the API. Within one root context, expansion merges preserve
  // every existing position (including dragged ones) and assign
  // deterministic positions only to genuinely new Entities.
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<EvolutionNodeData>>(initialNodes);
  const nodesRef = useRef(nodes);
  useEffect(() => {
    nodesRef.current = nodes;
  }, [nodes]);

  // Root context change -> deterministic radial reset; same context +
  // accumulated topology change -> in-place merge with position retention.
  const rootKeyRef = useRef<string | null>(null);
  useEffect(() => {
    const key = rootGraphKey;
    const rootChanged = rootKeyRef.current !== key;
    rootKeyRef.current = key;
    if (rootChanged) {
      setNodes(initialNodes);
      return;
    }
    // Same root graph context (PR 31E §6): keep every existing React Flow
    // node by canonical Entity ID with its current position, refresh
    // presentation data when server metadata changed, and create nodes
    // only for genuinely new Entities, placed deterministically near the
    // expanded anchor (falling back to the focal when a root overlay added
    // topology without an expansion).
    const currentNodes = nodesRef.current;
    const currentIds = new Set<string>();
    for (const rfNode of currentNodes) {
      const id = entityIdFromNodeId(rfNode.id);
      if (id !== null) {
        currentIds.add(id);
      }
    }
    const newEntityIds = model.nodes
      .filter((node) => !currentIds.has(node.entityId))
      .map((node) => node.entityId);
    const anchorEntityId =
      expansion.lastExpansion?.entityId ?? model.focal.entityId;
    const anchorNode = currentNodes.find(
      (node) => node.id === nodeId(anchorEntityId),
    );
    const anchorPosition: GraphPosition =
      anchorNode?.position ?? { x: 0, y: 0 };
    const occupied = new Map<string, GraphPosition>(
      currentNodes.map((node) => [node.id, node.position]),
    );
    const newPositions = positionsForExpandedNodes(
      anchorPosition,
      newEntityIds,
      occupied,
    );
    setNodes((prev) => {
      const byId = new Map(prev.map((node) => [node.id, node]));
      return model.nodes.map((node) => {
        const id = nodeId(node.entityId);
        const data: EvolutionNodeData = {
          label: node.label,
          role: node.role,
          entityTypeText: entityTypeLabel(node.entityType),
        };
        const existing = byId.get(id);
        if (existing === undefined) {
          return {
            id,
            type: "evolutionNode",
            position: newPositions.get(node.entityId) ?? { x: 0, y: 0 },
            data,
          };
        }
        return { ...existing, data: { ...existing.data, ...data } };
      });
    });
  }, [setNodes, rootGraphKey, initialNodes, model, expansion.lastExpansion, entityTypeLabel]);

  const edges: Edge[] = useMemo(
    () =>
      model.edges.map((edge) => ({
        id: edgeId(edge.relationshipId),
        source: nodeId(edge.sourceEntityId),
        target: nodeId(edge.targetEntityId),
        label: typeLabel(edge.relationshipType),
        type: "default",
      })),
    [model.edges, typeLabel],
  );

  const nodeById = useMemo(
    () => new Map(model.nodes.map((node) => [node.entityId, node])),
    [model.nodes],
  );

  const selectedEdge = useMemo(
    () =>
      selection?.kind === "edge"
        ? model.edges.find(
            (edge) => edge.relationshipId === relationshipIdFromEdgeId(selection.edgeId),
          ) ?? null
        : null,
    [selection, model.edges],
  );

  const selectedNode = useMemo(() => {
    if (selection?.kind !== "node") {
      return null;
    }
    const id = entityIdFromNodeId(selection.nodeId);
    return id === null ? null : (nodeById.get(id) ?? null);
  }, [selection, nodeById]);

  const truncatedEntities = useMemo(() => {
    const seen = new Set<string>();
    const result: { entityId: string; label: string }[] = [];
    for (const key of expansion.truncated) {
      if (seen.has(key.entityId)) {
        continue;
      }
      seen.add(key.entityId);
      const node = nodeById.get(key.entityId);
      result.push({
        entityId: key.entityId,
        label: node?.label ?? graphLabel(key.entityId),
      });
    }
    return result;
  }, [expansion.truncated, nodeById]);

  return (
    <Box>
      {model.truncated ? (
        <Alert severity="info" role="status" sx={{ mb: 1 }}>
          {t("graph.boundedNotice")}
        </Alert>
      ) : null}
      {expansion.inFlight !== null ? (
        <Alert severity="info" role="status" sx={{ mb: 1 }}>
          {t("graph.expansion.loading")}
        </Alert>
      ) : null}
      {expansion.failed !== null ? (
        <Alert severity="error" role="alert" sx={{ mb: 1 }}>
          {t("graph.expansion.error")}
          <Button
            size="small"
            variant="outlined"
            onClick={() => expansion.retry()}
            sx={{ ml: 1, textTransform: "none" }}
          >
            {t("error.retry")}
          </Button>
        </Alert>
      ) : null}
      {truncatedEntities.map((entry) => (
        <Alert
          key={entry.entityId}
          severity="info"
          role="status"
          sx={{ mb: 1 }}
        >
          {t("graph.expansion.truncated", { label: entry.label })}
        </Alert>
      ))}
      <Box sx={{ mb: 1 }}>
        <Link
          href={`/investigations/${investigationId}/relationships?entity_id=${model.focal.entityId}`}
          underline="hover"
        >
          {t("graph.openTable")}
        </Link>
      </Box>
      <Box
        sx={{ height: size.height, border: 1, borderColor: "divider", borderRadius: 1 }}
        aria-label={t("graph.canvasLabel")}
        role="group"
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.25 }}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
          minZoom={0.25}
          maxZoom={2}
          deleteKeyCode={null}
          onNodesChange={onNodesChange}
          onNodeClick={(_event, node) => setSelection({ kind: "node", nodeId: node.id })}
          onEdgeClick={(_event, edge) => setSelection({ kind: "edge", edgeId: edge.id })}
          onPaneClick={() => setSelection(null)}
        >
          <Background />
          <Controls />
        </ReactFlow>
      </Box>

      {selectedNode !== null ? (
        <Box sx={{ mt: 1.5, p: 1, border: 1, borderColor: "divider", borderRadius: 1 }}>
          <Typography variant="subtitle2" component="h4">
            {t("graph.nodeSelection", { label: selectedNode.label })}
          </Typography>
          <DetailRows
            rows={[
              {
                label: t("graph.detail.entityId"),
                value: <CompactId id={selectedNode.entityId} label={t("graph.detail.entityId")} />,
              },
              {
                label: t("graph.detail.entityType"),
                value: entityTypeLabel(selectedNode.entityType),
              },
              { label: t("graph.detail.value"), value: selectedNode.value },
              ...(selectedNode.displayName !== null &&
              selectedNode.displayName.trim() !== ""
                ? [{ label: t("graph.detail.displayName"), value: selectedNode.displayName }]
                : []),
            ]}
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 0.5 }}>
            <PivotMenu
              actions={entityActions(selectedNode.entityId, selectedNode.label, "detail_field")}
              localActions={expansionLocalActions(
                t as never,
                selectedNode.entityId,
                expansion,
              )}
              ariaLabel={t("graph.pivotAria", { label: selectedNode.label })}
            />
            <Button
              size="small"
              component="a"
              href={evolutionLink(investigationId, selectedNode.entityId)}
              sx={{ textTransform: "none" }}
            >
              {t("graph.viewEvolution")}
            </Button>
          </Box>
        </Box>
      ) : null}

      {selectedEdge !== null ? (
        <Box sx={{ mt: 1.5, p: 1, border: 1, borderColor: "divider", borderRadius: 1 }}>
          <Typography variant="subtitle2" component="h4">
            {t("graph.edgeSelection", {
              type: typeLabel(selectedEdge.relationshipType),
            })}
          </Typography>
          <DetailRows
            rows={[
              {
                label: t("graph.detail.relationshipId"),
                value: (
                  <CompactId
                    id={selectedEdge.relationshipId}
                    label={t("graph.detail.relationshipId")}
                  />
                ),
              },
              {
                label: t("graph.detail.relationshipType"),
                value: typeLabel(selectedEdge.relationshipType),
              },
              {
                label: t("graph.detail.sourceEntity"),
                value: entitySummary(
                  nodeById.get(selectedEdge.sourceEntityId),
                  selectedEdge.sourceEntityId,
                  t,
                ),
              },
              {
                label: t("graph.detail.targetEntity"),
                value: entitySummary(
                  nodeById.get(selectedEdge.targetEntityId),
                  selectedEdge.targetEntityId,
                  t,
                ),
              },
              {
                label: t("graph.detail.observationCount"),
                value: String(selectedEdge.observationCount),
              },
              {
                label: t("graph.detail.firstObserved"),
                value:
                  selectedEdge.firstObservedAt !== null
                    ? <Timestamp iso={selectedEdge.firstObservedAt} />
                    : t("graph.detail.unavailable"),
              },
              {
                label: t("graph.detail.lastObserved"),
                value:
                  selectedEdge.lastObservedAt !== null
                    ? <Timestamp iso={selectedEdge.lastObservedAt} />
                    : t("graph.detail.unavailable"),
              },
            ]}
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 0.5 }}>
            <Button
              size="small"
              component="a"
              href={`/investigations/${investigationId}/relationships?selected=${selectedEdge.relationshipId}`}
              sx={{ textTransform: "none" }}
            >
              {t("graph.viewRelationship")}
            </Button>
            <PivotMenu
              actions={[relationshipObservationsAction(selectedEdge.relationshipId, "detail_field")]}
              ariaLabel={t("graph.observationsAria")}
            />
          </Box>
        </Box>
      ) : null}

      {model.edges.length === 0 ? (
        <Typography variant="body2" sx={{ py: 2, textAlign: "center" }}>
          {t("graph.empty")}
        </Typography>
      ) : null}

      <Box component="section" aria-label={t("graph.listHeading")} sx={{ mt: 2 }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>
          {t("graph.listHeading")}
        </Typography>
        <EdgeList
          t={t}
          investigationId={investigationId}
          focalEntityId={focalEntityId}
          model={model}
          nodeById={nodeById}
          typeLabel={typeLabel}
        />
      </Box>
    </Box>
  );
}

/** Node id scheme (graph-local; entity UUIDs stay authoritative). */
export function nodeId(entityId: string): string {
  return `n:${entityId}`;
}

/** Reverse the node id scheme; null for foreign ids. */
export function entityIdFromNodeId(id: string): string | null {
  return id.startsWith("n:") ? id.slice(2) : null;
}

/** Edge id scheme (graph-local; relationship UUID stays authoritative). */
export function edgeId(relationshipId: string): string {
  return `e:${relationshipId}`;
}

/** Reverse the edge id scheme; null for foreign ids. */
export function relationshipIdFromEdgeId(id: string): string | null {
  return id.startsWith("e:") ? id.slice(2) : null;
}

/** Fallback compact graph label when a node is not on the page. */
function graphLabel(entityId: string): string {
  return `Entity ${entityId.slice(0, 8)}`;
}

/**
 * The three bounded local graph-expansion commands (PR 31E §19-§20).
 *
 * Expansion directions are relative to the selected Entity: known/all maps
 * to ``either``, outgoing to ``source``, incoming to ``target``. The exact
 * (entity, direction) expansion hides/disabled once completed and every
 * expansion action is disabled while another expansion is in flight. These
 * are local UI commands — never PivotSteps, never stored in the URL, never
 * depth-limited or no-op-suppressed by the pivot stack.
 */
function expansionLocalActions(
  t: TFunction,
  entityId: string,
  expansion: GraphExpansionController,
): PivotLocalAction[] {
  const inFlight = expansion.inFlight !== null;
  const make = (
    key: string,
    labelKey: string,
    direction: RelationshipDirectionName,
  ): PivotLocalAction => ({
    key,
    label: t(labelKey),
    disabled: inFlight || expansion.isExpanded(entityId, direction),
    onSelect: () => expansion.expand(entityId, direction),
  });
  return [
    make("graph-expand-either", "graph.expand.known", "either"),
    make("graph-expand-source", "graph.expand.outgoing", "source"),
    make("graph-expand-target", "graph.expand.incoming", "target"),
  ];
}

/** The evolution route link for one entity. */
export function evolutionLink(investigationId: string, entityId: string): string {
  return `/investigations/${investigationId}/relationships/evolution?entity_id=${entityId}`;
}

/** One entity line: human-readable value + exact canonical identity access. */
function entitySummary(
  node: RelationshipGraphNode | undefined,
  entityId: string,
  t: TFunction,
): ReactElement {
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
      <Box component="span" sx={{ fontWeight: 600 }}>
        {node?.label ?? graphLabel(entityId)}
      </Box>
      <CompactId id={entityId} label={t("graph.detail.entityId")} />
    </Box>
  );
}

/** Edge-list navigation table (the always-loaded accessible alternative). */
function EdgeList({
  t,
  investigationId,
  focalEntityId,
  model,
  nodeById,
  typeLabel,
}: {
  t: TFunction;
  investigationId: string;
  focalEntityId: string;
  model: RelationshipGraphModel;
  nodeById: Map<string, RelationshipGraphNode>;
  typeLabel: (type: string) => string;
}): ReactElement {
  return (
    <Box sx={{ overflowX: "auto" }}>
      <table
        aria-label={t("graph.listHeading")}
        style={{ borderCollapse: "collapse", width: "100%" }}
      >
        <thead>
          <tr>
            {[
              t("graph.list.type"),
              t("graph.list.source"),
              t("graph.list.target"),
              t("graph.list.supportingObservations"),
              t("graph.list.firstObserved"),
              t("graph.list.lastObserved"),
              t("graph.list.action"),
            ].map((header) => (
              <th key={header} scope="col" style={{ textAlign: "left", padding: 6 }}>
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {model.edges.map((edge) => {
            const source = nodeById.get(edge.sourceEntityId);
            const target = nodeById.get(edge.targetEntityId);
            const counterpartyId =
              edge.sourceEntityId === focalEntityId
                ? edge.targetEntityId
                : edge.sourceEntityId;
            return (
              <tr key={edge.relationshipId}>
                <td style={{ padding: 6 }}>{typeLabel(edge.relationshipType)}</td>
                <td style={{ padding: 6 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Box component="span">{source?.label ?? graphLabel(edge.sourceEntityId)}</Box>
                    <CompactId id={edge.sourceEntityId} label={t("graph.detail.entityId")} />
                  </Box>
                </td>
                <td style={{ padding: 6 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Box component="span">{target?.label ?? graphLabel(edge.targetEntityId)}</Box>
                    <CompactId id={edge.targetEntityId} label={t("graph.detail.entityId")} />
                  </Box>
                </td>
                <td style={{ padding: 6 }}>{String(edge.observationCount)}</td>
                <td style={{ padding: 6 }}>
                  {edge.firstObservedAt !== null
                    ? <Timestamp iso={edge.firstObservedAt} />
                    : t("graph.detail.unavailable")}
                </td>
                <td style={{ padding: 6 }}>
                  {edge.lastObservedAt !== null
                    ? <Timestamp iso={edge.lastObservedAt} />
                    : t("graph.detail.unavailable")}
                </td>
                <td style={{ padding: 6 }}>
                  <Button
                    size="small"
                    component="a"
                    href={`/investigations/${investigationId}/relationships?selected=${edge.relationshipId}`}
                    sx={{ textTransform: "none" }}
                  >
                    {t("graph.list.view")}
                  </Button>
                  <Button
                    size="small"
                    component="a"
                    href={evolutionLink(investigationId, counterpartyId)}
                    sx={{ textTransform: "none" }}
                  >
                    {t("graph.list.viewEvolution")}
                  </Button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Box>
  );
}
