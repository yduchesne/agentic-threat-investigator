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

import { Alert, Box, Button, Link, Tooltip, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import {
  Background,
  ControlButton,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  useNodes,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { CSSProperties, ReactElement } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Link as RouterLink, useLocation } from "react-router";

import {
  internalLocationFromPath,
  navigationState,
  pushNavigationReturn,
} from "../analyst-table/return-to";

import { CompactId } from "../components/CompactId";
import type { AtiSemanticTokens } from "../app/theme";
import { Timestamp } from "../components/Timestamp";
import { DetailRows } from "../analyst-table/DetailRows";
import { PivotMenu, type PivotLocalAction } from "../pivots/PivotMenu";
import { entityActions } from "../pivots/pivot-capabilities";
import { relationshipObservationsAction } from "../pivots/pivot-capabilities";
import type { RelationshipDirectionName } from "../api/schema-types";
import type {
  RelationshipGraphEdge,
  RelationshipGraphModel,
  RelationshipGraphNode,
} from "./relationship-graph-model";
import {
  layoutRelationshipGraph,
  layoutSize,
  positionsForExpandedNodes,
  type GraphPosition,
} from "./relationship-graph-layout";
import type { GraphExpansionController } from "./use-graph-expansion";
import { GraphRelationshipProvenance } from "./GraphRelationshipProvenance";

/** One custom React Flow node backed by an exact Entity ID. */
export type EvolutionNodeData = {
  /** Canonical Entity value (never synthesized from a UUID). */
  entityValue: string;
  /** Visible entity-type cue (never a color-only differentiation). */
  entityTypeText: string;
  /** Optional server display name; rendered only when distinct from value. */
  displayName: string | null;
  role: "focal" | "counterparty";
  /** PR 31I: path-mode endpoint role of the node, when selected. */
  pathEndpoint?: "source" | "target";
  /** PR 31I: node participates in the currently highlighted path. */
  pathHighlighted?: boolean;
  /** PR 31I: node is outside the currently highlighted path. */
  pathDimmed?: boolean;
} & Record<string, unknown>;

const nodeTypes: NodeTypes = { evolutionNode: EvolutionGraphNode };

function EvolutionGraphNode({ data }: NodeProps): ReactElement {
  const nodeData = data as EvolutionNodeData;
  const value = nodeData.entityValue.trim();
  const displayName =
    nodeData.displayName !== null &&
    nodeData.displayName.trim() !== "" &&
    nodeData.displayName.trim() !== value
      ? nodeData.displayName.trim()
      : null;
  return (
    <Box
      sx={{
        px: 1.5,
        py: 0.75,
        border: 2,
        borderRadius: 999,
        borderColor:
          nodeData.pathEndpoint === "source"
            ? "primary.main"
            : nodeData.pathEndpoint === "target"
              ? "secondary.main"
              : nodeData.role === "focal"
                ? "primary.main"
                : "divider",
        bgcolor: nodeData.role === "focal" ? "primary.main" : "background.paper",
        color: nodeData.role === "focal" ? "primary.contrastText" : "text.primary",
        opacity: nodeData.pathDimmed ? 0.4 : 1,
        boxShadow:
          nodeData.pathHighlighted
            ? (theme) => `0 0 0 3px ${theme.palette.primary.main}`
            : undefined,
        fontSize: 12,
        fontFamily: "monospace",
        whiteSpace: "nowrap",
        maxWidth: 220,
        overflow: "hidden",
        textOverflow: "ellipsis",
      }}
    >
      {/* Handle slots: canonical edge routing anchors (PR 31F-1). Each
       * canonical Relationship gets a deterministic slot so parallel
       * Relationships between the same endpoint pair draw visibly separated
       * paths, and a canonical self-loop draws a visible arc instead of a
       * zero-length sliver. Slot handles reuse the historical bottom/top
       * idiom with distinct x offsets. */}
      <Handle type="target" id="target-top-0" position={Position.Top} style={{ left: "50%", opacity: 0 }} />
      <Handle type="target" id="target-top-1" position={Position.Top} style={{ left: "25%", opacity: 0 }} />
      <Handle type="target" id="target-top-2" position={Position.Top} style={{ left: "75%", opacity: 0 }} />
      <Handle type="target" id="target-loop" position={Position.Top} style={{ left: "80%", opacity: 0 }} />
      <Handle type="source" id="source-bottom-0" position={Position.Bottom} style={{ left: "50%", opacity: 0 }} />
      <Handle type="source" id="source-bottom-1" position={Position.Bottom} style={{ left: "25%", opacity: 0 }} />
      <Handle type="source" id="source-bottom-2" position={Position.Bottom} style={{ left: "75%", opacity: 0 }} />
      <Handle type="source" id="source-loop" position={Position.Bottom} style={{ left: "20%", opacity: 0 }} />
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
      {value}
      {displayName !== null ? (
        <Box
          component="span"
          sx={{ display: "block", fontSize: 10, fontFamily: "sans-serif", opacity: 0.85 }}
        >
          {displayName}
        </Box>
      ) : null}
    </Box>
  );
}

/** Estimated rendered size of the graph right-click context menu (clamp). */
export const GRAPH_CONTEXT_MENU_WIDTH = 200;
export const GRAPH_CONTEXT_MENU_HEIGHT = 44;

/** One open graph right-click context menu: canonical ID + pointer offset. */
export interface GraphContextMenuState {
  /** Canonical Entity ID of the right-clicked non-focal node. */
  entityId: string;
  /** Pointer x relative to the graph container's top-left corner. */
  x: number;
  /** Pointer y relative to the graph container's top-left corner. */
  y: number;
}

/**
 * Clamp a pointer-adjacent menu position inside the graph container.
 *
 * The menu is positioned out of document flow at the pointer; this pure
 * helper keeps it fully visible by flipping back from the container's
 * right/bottom edges without ever moving the canvas. Exported so the edge
 * behaviour is unit-testable without a layout engine.
 */
export function clampContextMenuPosition(
  x: number,
  y: number,
  containerWidth: number,
  containerHeight: number,
  menuWidth: number = GRAPH_CONTEXT_MENU_WIDTH,
  menuHeight: number = GRAPH_CONTEXT_MENU_HEIGHT,
): { x: number; y: number } {
  const maxX = Math.max(0, containerWidth - menuWidth);
  const maxY = Math.max(0, containerHeight - menuHeight);
  return {
    x: Math.min(Math.max(0, x), maxX),
    y: Math.min(Math.max(0, y), maxY),
  };
}

/** Fit padding shared by automatic and explicit graph framing (PR 38-10). */
export const GRAPH_FIT_PADDING = 0.25;

/** Minimal inline Fit-to-view glyph (decorative; the button is named). */
function FitViewIcon(): ReactElement {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
    >
      <path
        fill="currentColor"
        d="M4 4h6v2H6v4H4V4zm10 0h6v6h-2V6h-4V4zM4 14h2v4h4v2H4v-6zm14 0h2v6h-6v-2h4v-4z"
      />
    </svg>
  );
}

/**
 * The existing bottom-left React Flow controls plus ATI's explicit,
 * localized Fit graph to view action (PR 38-10 Step 16).
 *
 * The built-in Fit View control does not expose a localizable per-button
 * accessible name, so the same panel hosts a ``ControlButton`` that calls
 * React Flow ``fitView`` with the shared padding policy. Fitting changes
 * only viewport pan/zoom: it never invokes Dagre and never mutates node
 * coordinates.
 *
 * The same component performs one automatic fit after each new root
 * topology is committed: it waits until the React Flow store reflects the
 * expected root Entity set (``useNodes``/``useNodesInitialized``, never a
 * timer), then fits once per root graph key. The key includes the model's
 * canonical root Entity so the stale intermediate commit of a focal
 * re-root (new graph key, previous root's model) cannot mark the correct
 * root topology as already fitted and skip its fit. Same-root expansion and
 * ordinary interaction therefore never re-fit or re-layout.
 */
function GraphControls({
  rootGraphKey,
  expectedEntityIds,
}: {
  rootGraphKey: string;
  expectedEntityIds: readonly string[];
}): ReactElement {
  const { t } = useTranslation("relationshipEvolution");
  const { fitView } = useReactFlow();
  const nodes = useNodes();
  const nodesInitialized = useNodesInitialized();
  const fittedRootKey = useRef<string | null>(null);
  useEffect(() => {
    if (!nodesInitialized || fittedRootKey.current === rootGraphKey) {
      return;
    }
    // The root state change commits in two phases (new key, then nodes), so
    // wait until the React Flow store actually carries this root's Entities
    // before fitting; the controlled node set always matches the model.
    const currentIds = new Set(nodes.map((node) => node.id));
    const expectedIds = expectedEntityIds.map(nodeId);
    if (
      currentIds.size !== expectedIds.length ||
      !expectedIds.every((id) => currentIds.has(id))
    ) {
      return;
    }
    fittedRootKey.current = rootGraphKey;
    void fitView({ padding: GRAPH_FIT_PADDING });
  }, [nodesInitialized, nodes, rootGraphKey, expectedEntityIds, fitView]);
  return (
    <Controls showFitView={false}>
      <ControlButton
        aria-label={t("graph.fitView")}
        title={t("graph.fitView")}
        onClick={() => {
          void fitView({ padding: GRAPH_FIT_PADDING });
        }}
      >
        <FitViewIcon />
      </ControlButton>
    </Controls>
  );
}

export interface RelationshipGraphProps {
  investigationId: string;
  /** Root graph context key (investigation/focal/direction/type/depth); a
   * change resets the deterministic root layout and dropped expansion state. */
  rootGraphKey: string;
  focalEntityId: string;
  model: RelationshipGraphModel;
  /** PR 31H: true when the committed depth is 2/3 (multi-hop traversal). */
  multiHop?: boolean;
  /** Relationship type URN -> analyst label. */
  typeLabel: (type: string) => string;
  /** Entity type -> analyst label (exact text, non-color differentiation). */
  entityTypeLabel: (type: string) => string;
  /** PR 31E analyst-driven expansion controller (owned by the workspace). */
  expansion: GraphExpansionController;
  /** PR 31J: override the ordinary empty-state wording (temporal empty frame). */
  emptyMessage?: string | undefined;
  /** PR 31I: path-finding mode active: node clicks select endpoints. */
  pathMode?: boolean;
  /** PR 31I: analyst-selected canonical path endpoints (source/target). */
  pathEndpoints?: { source: string | null; target: string | null } | null;
  /** PR 31I: propagate a path-endpoint node click to the workspace. */
  onPathEndpointClick?: (entityId: string) => void;
  /**
   * PR 31K: propagate a path-mode-off node click as a bounded graph-action
   * selection to the workspace. Never invoked while path mode is active:
   * PR 31I endpoint-selection semantics keep click precedence.
   */
  onActionSelect?: (entityId: string) => void;
  /**
   * PR 31I: the canonical ID sets of the currently highlighted path. When
   * present, participating edges/nodes are emphasized and everything else in
   * the returned path topology is dimmed; ``null`` means no highlight.
   */
  pathHighlight?: {
    relationshipIds: ReadonlySet<string>;
    entityIds: ReadonlySet<string>;
  } | null;
  /**
   * PR 35-8: invoke the graph-local focal Explore command with the exact
   * canonical Entity ID of a right-clicked node. The graph never owns URL
   * navigation; the workspace commits the focal change.
   */
  onExploreEntity?: (entityId: string) => void;
}

/** The bounded accumulated graph surface with an always-available list path. */
export function RelationshipGraph({
  investigationId,
  rootGraphKey,
  focalEntityId,
  model,
  multiHop = false,
  typeLabel,
  entityTypeLabel,
  expansion,
  pathMode = false,
  pathEndpoints = undefined,
  onPathEndpointClick,
  onActionSelect,
  pathHighlight = null,
  emptyMessage = undefined,
  onExploreEntity = undefined,
}: RelationshipGraphProps): ReactElement {
  const { t } = useTranslation("relationshipEvolution");
  const location = useLocation();
  // PR 35-1 Part 3: the graph is an internal entry point to Relationship
  // history; push the exact graph surface so the workspace can offer a
  // contextual Back to this graph view while retaining ancestors.
  const drillDownState = navigationState(
    pushNavigationReturn(
      location.state,
      internalLocationFromPath(location.pathname, location.search, location.hash),
    ),
  );
  // PR 31F-4: the active theme's semantic graph tokens drive canvas, edge,
  // node and control presentation. Topology/query/expansion semantics never
  // read theme state: only the presentation boundary below consumes tokens.
  const graphTokens = useTheme().ati.graph;
  const graphFlowStyle = graphCssVariables(useTheme().ati);
  const [selection, setSelection] = useState<
    { kind: "node"; nodeId: string } | { kind: "edge"; edgeId: string } | null
  >(null);
  // PR 31F: the canonical Relationship whose provenance panel is open.
  // Drill-down is transient presentation state local to the graph; it
  // never touches nodes/positions/expansion state and never mutates the
  // URL. A selection change closes it so provenance never survives the
  // edge context that opened it.
  const [provenanceRelationshipId, setProvenanceRelationshipId] = useState<
    string | null
  >(null);
  // PR 35-8 amendment 1: the lightweight pointer-adjacent right-click context
  // menu. It owns only the canonical Entity ID and the pointer position
  // relative to the graph container. It is ordinary positioned content (no
  // portal, backdrop, focus trap, body lock or persistent pointer shield) and
  // closes deterministically on Explore, Escape, outside pointer, retarget,
  // root change or unmount.
  const [contextMenu, setContextMenu] = useState<GraphContextMenuState | null>(
    null,
  );
  const canvasContainerRef = useRef<HTMLDivElement | null>(null);
  const contextMenuRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    setProvenanceRelationshipId(null);
  }, [selection]);
  // A root semantic change (focal Explore re-roots the graph) clears stale
  // selection, provenance and context-menu state so no prior-root detail
  // survives the transition.
  useEffect(() => {
    setSelection(null);
    setProvenanceRelationshipId(null);
    setContextMenu(null);
  }, [rootGraphKey]);
  // The menu registers a document key/pointer listener ONLY while it is open
  // and removes it deterministically on close/unmount. The listeners never
  // prevent default or stop propagation, so they can never intercept graph
  // pan/zoom/drag/click input after the menu closes.
  const contextMenuOpen = contextMenu !== null;
  useEffect(() => {
    if (!contextMenuOpen) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        setContextMenu(null);
      }
    };
    const onMouseDown = (event: MouseEvent): void => {
      if (contextMenuRef.current?.contains(event.target as globalThis.Node)) {
        return;
      }
      setContextMenu(null);
    };
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("mousedown", onMouseDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("mousedown", onMouseDown);
    };
  }, [contextMenuOpen]);

  const positions = useMemo(
    () => layoutRelationshipGraph(focalEntityId, model.nodes, model.edges),
    [focalEntityId, model.nodes, model.edges],
  );
  const size = useMemo(() => layoutSize(positions.values()), [positions]);
  const expectedEntityIds = useMemo(
    () => model.nodes.map((node) => node.entityId),
    [model.nodes],
  );

  const initialNodes: Node<EvolutionNodeData>[] = useMemo(
    () =>
      model.nodes.map((node) => ({
        id: nodeId(node.entityId),
        type: "evolutionNode" as const,
        position: positions.get(node.entityId) ?? { x: 0, y: 0 },
        data: {
          entityValue: node.value,
          role: node.entityId === focalEntityId ? "focal" : "counterparty",
          entityTypeText: entityTypeLabel(node.entityType),
          displayName: node.displayName,
        },
      })),
    [model.nodes, focalEntityId, positions, entityTypeLabel],
  );

  // PR 31I: path-mode presentation decorations are derived per render so
  // endpoint selection, the displayed result and the highlighted path never
  // mutate React Flow node state.
  const decoratedInitialNodes: Node<EvolutionNodeData>[] = useMemo(() => {
    const activeHighlight = pathHighlight;
    return initialNodes.map((node) => {
      const entityId = entityIdFromNodeId(node.id);
      if (entityId === null) {
        return node;
      }
      const data: EvolutionNodeData = {
        ...node.data,
        pathEndpoint:
          entityId === pathEndpoints?.source
            ? "source"
            : entityId === pathEndpoints?.target
              ? "target"
              : undefined,
        pathHighlighted: activeHighlight?.entityIds.has(entityId) ?? false,
        pathDimmed:
          activeHighlight !== null && !activeHighlight.entityIds.has(entityId),
      };
      return { ...node, data };
    });
  }, [initialNodes, pathEndpoints, pathHighlight]);

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
  //
  // The reset is keyed on BOTH the URL/filter root graph key and the model's
  // canonical root Entity. A focal re-root commits the new root graph key
  // one render before the expansion controller swaps in the new accumulated
  // model (child effects run before parent effects), so keying on the graph
  // key alone would reset positions from the previous root's model and then
  // misclassify the correct model as same-root expansion growth, producing
  // overlapping ring-placed nodes. Tracking the model root makes the stale
  // intermediate commit reset again once the correct model arrives.
  const rootKeyRef = useRef<string | null>(null);
  const rootEntityRef = useRef<string | null>(null);
  useEffect(() => {
    const key = rootGraphKey;
    const modelRoot = model.focal.entityId;
    const rootChanged =
      rootKeyRef.current !== key || rootEntityRef.current !== modelRoot;
    rootKeyRef.current = key;
    rootEntityRef.current = modelRoot;
    const baseNodes = rootChanged ? decoratedInitialNodes : nodesRef.current;
    if (rootChanged) {
      setNodes(decoratedInitialNodes);
      return;
    }
    // Same root graph context (PR 31E §6): keep every existing React Flow
    // node by canonical Entity ID with its current position, refresh
    // presentation data when server metadata changed, and create nodes
    // only for genuinely new Entities, placed deterministically near the
    // expanded anchor (falling back to the focal when a root overlay added
    // topology without an expansion).
    const currentNodes = baseNodes;
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
          entityValue: node.value,
          role: node.entityId === focalEntityId ? "focal" : "counterparty",
          entityTypeText: entityTypeLabel(node.entityType),
          displayName: node.displayName,
          pathEndpoint:
            node.entityId === pathEndpoints?.source
              ? "source"
              : node.entityId === pathEndpoints?.target
                ? "target"
                : undefined,
          pathHighlighted: pathHighlight?.entityIds.has(node.entityId) ?? false,
          pathDimmed:
            pathHighlight !== null &&
            !pathHighlight.entityIds.has(node.entityId),
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
  }, [
    setNodes,
    rootGraphKey,
    decoratedInitialNodes,
    model,
    focalEntityId,
    expansion.lastExpansion,
    entityTypeLabel,
    pathEndpoints,
    pathHighlight,
  ]);

  const edges: Edge[] = useMemo(() => {
    const renderedEntityIds = new Set(nodes.map((node) => entityIdFromNodeId(node.id)).filter((id): id is string => id !== null));
    const canonicalEntityIds = new Set(model.nodes.map((node) => node.entityId));
    const renderableEdges = selectRenderableEdges(
      model.edges,
      canonicalEntityIds,
      renderedEntityIds,
    );
    return buildSlottedEdges(
      renderableEdges,
      typeLabel,
      graphTokens.edge.default,
      {
        highlightedRelationshipIds: pathHighlight?.relationshipIds ?? null,
        highlightedColor: graphTokens.edge.selected,
        dimmedColor: graphTokens.edge.default,
        dimmedOpacity: 0.3,
      },
    );
  }, [model.edges, nodes, typeLabel, graphTokens.edge.default, graphTokens.edge.selected, pathHighlight]);

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

  // The canonical node backing the right-click context menu; a stale or
  // non-canonical Entity ID resolves to null and suppresses the menu.
  const contextNode = useMemo(
    () => (contextMenu === null ? null : nodeById.get(contextMenu.entityId) ?? null),
    [contextMenu, nodeById],
  );

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
          {multiHop ? t("graph.multihopBoundedNotice") : t("graph.boundedNotice")}
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
      <Box
        ref={canvasContainerRef}
        sx={{
          position: "relative",
          height: size.height,
          border: 1,
          borderColor: "divider",
          borderRadius: 1,
        }}
        style={graphFlowStyle}
        aria-label={t("graph.canvasLabel")}
        role="group"
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: GRAPH_FIT_PADDING }}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
          minZoom={0.25}
          maxZoom={2}
          deleteKeyCode={null}
          onNodesChange={onNodesChange}
          onNodeClick={(_event, node) => {
            if (pathMode && onPathEndpointClick !== undefined) {
              const entityId = entityIdFromNodeId(node.id);
              if (entityId !== null) {
                onPathEndpointClick(entityId);
                return;
              }
            }
            setSelection({ kind: "node", nodeId: node.id });
            const entityId = entityIdFromNodeId(node.id);
            if (entityId !== null) {
              onActionSelect?.(entityId);
            }
          }}
          onEdgeClick={(_event, edge) => setSelection({ kind: "edge", edgeId: edge.id })}
          onPaneClick={() => setSelection(null)}
          onNodeContextMenu={(event, node) => {
            // The graph node is an app surface with a graph-local context
            // action: never let the browser menu take over a handled node.
            event.preventDefault();
            const entityId = entityIdFromNodeId(node.id);
            if (entityId === null || !nodeById.has(entityId)) {
              return;
            }
            // The focal node offers no Explore; do not open a menu for it.
            if (entityId === focalEntityId || onExploreEntity === undefined) {
              return;
            }
            const bounds = canvasContainerRef.current?.getBoundingClientRect();
            const rawX = bounds === undefined ? event.clientX : event.clientX - bounds.left;
            const rawY = bounds === undefined ? event.clientY : event.clientY - bounds.top;
            const position = clampContextMenuPosition(
              rawX,
              rawY,
              bounds?.width ?? Number.POSITIVE_INFINITY,
              bounds?.height ?? Number.POSITIVE_INFINITY,
            );
            setContextMenu({ entityId, x: position.x, y: position.y });
          }}
        >
          <Background />
          <GraphControls
            rootGraphKey={`${rootGraphKey}\u0000${model.focal.entityId}`}
            expectedEntityIds={expectedEntityIds}
          />
        </ReactFlow>
        {contextNode !== null && contextMenu !== null ? (
          <Box
            ref={contextMenuRef}
            data-ati-id="graph.entity-context-menu"
            role="group"
            aria-label={t("graph.contextMenu.aria")}
            onMouseDown={(event) => event.stopPropagation()}
            sx={{
              position: "absolute",
              left: contextMenu.x,
              top: contextMenu.y,
              zIndex: 10,
              display: "flex",
              alignItems: "center",
              gap: 0.5,
              p: 0.5,
              border: 1,
              borderColor: "divider",
              borderRadius: 1,
              bgcolor: "background.paper",
              boxShadow: 3,
            }}
          >
            <Typography variant="caption" component="span" sx={{ px: 0.5 }}>
              {contextNode.label}
            </Typography>
            <Button
              size="small"
              variant="text"
              data-testid="graph-explore-entity"
              onClick={() => {
                const target = contextMenu.entityId;
                setContextMenu(null);
                onExploreEntity?.(target);
              }}
              sx={{ textTransform: "none" }}
            >
              {t("graph.explore")}
            </Button>
          </Box>
        ) : null}
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
              component={RouterLink}
              to={evolutionLink(investigationId, selectedNode.entityId)}
              state={drillDownState}
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
                label: t("graph.detail.matchingObservations"),
                value: String(selectedEdge.observationCount),
              },
              {
                label: t("graph.detail.matchingInvestigation"),
                value: String(selectedEdge.investigationObservationCount),
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
          <Typography
            variant="caption"
            component="div"
            role="status"
            aria-label={edgeContextLabel(t, selectedEdge)}
            sx={{ mt: 1, fontWeight: 600 }}
          >
            {edgeContextLabel(t, selectedEdge)}
          </Typography>
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
            <Button
              size="small"
              variant="outlined"
              onClick={() =>
                setProvenanceRelationshipId(
                  provenanceRelationshipId === selectedEdge.relationshipId
                    ? null
                    : selectedEdge.relationshipId,
                )
              }
              sx={{ textTransform: "none" }}
            >
              {t("graph.provenance.inspect")}
            </Button>
          </Box>
        </Box>
      ) : null}

      {provenanceRelationshipId !== null ? (
        <GraphRelationshipProvenance
          investigationId={investigationId}
          relationshipId={provenanceRelationshipId}
          sourceNode={nodeById.get(model.edges.find((edge) => edge.relationshipId === provenanceRelationshipId)?.sourceEntityId ?? "") ?? null}
          targetNode={nodeById.get(model.edges.find((edge) => edge.relationshipId === provenanceRelationshipId)?.targetEntityId ?? "") ?? null}
          entityTypeLabel={entityTypeLabel}
          knownOnly={
            model.edges.find(
              (edge) => edge.relationshipId === provenanceRelationshipId,
            )?.investigationObservationCount === 0
          }
          onClose={() => setProvenanceRelationshipId(null)}
        />
      ) : null}

      {model.edges.length === 0 ? (
        <Typography variant="body2" sx={{ py: 2, textAlign: "center" }}>
          {emptyMessage ?? t("graph.empty")}
        </Typography>
      ) : null}

      <Box component="section" aria-label={t("graph.listHeading")} sx={{ mt: 2 }}>
        <EdgeList
          t={t}
          investigationId={investigationId}
          focalEntityId={focalEntityId}
          model={model}
          nodeById={nodeById}
          typeLabel={typeLabel}
          entityTypeLabel={entityTypeLabel}
          drillDownState={drillDownState}
          onInspectObservations={(relationshipId) =>
            setProvenanceRelationshipId(relationshipId)
          }
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

/**
 * Map semantic graph tokens onto React Flow's public CSS-variable surface.
 *
 * Only ATI-owned presentation is themed (canvas, pattern, edges, edge
 * labels, selection frame, handles, controls); topology, IDs, positions
 * and expansion semantics never flow through here.
 */
export function graphCssVariables(tokens: AtiSemanticTokens): CSSProperties {
  const variables = {
    "--xy-background-color": tokens.graph.canvas,
    "--xy-background-pattern-dots-color": tokens.graph.pattern,
    "--xy-edge-stroke": tokens.graph.edge.default,
    "--xy-edge-stroke-selected": tokens.graph.edge.selected,
    "--xy-edge-label-background-color": tokens.graph.edge.label,
    "--xy-edge-label-color": tokens.text.technical,
    "--xy-node-border": `1px solid ${tokens.graph.node.border}`,
    "--xy-node-background-color": tokens.graph.node.background,
    "--xy-node-color": tokens.graph.node.text,
    "--xy-node-boxshadow-selected": `0 0 0 1px ${tokens.graph.node.selected}`,
    "--xy-node-boxshadow-hover": `0 0 0 1px ${tokens.graph.node.border}`,
    "--xy-handle-background-color": tokens.graph.node.selected,
    "--xy-handle-border-color": tokens.graph.node.border,
    "--xy-selection-background-color": tokens.selection.background,
    "--xy-selection-border": `1px dotted ${tokens.selection.border}`,
    "--xy-controls-button-background-color": tokens.surface.elevated,
    "--xy-controls-button-background-color-hover": tokens.surface.subtle,
    "--xy-controls-button-color": tokens.text.primary,
    "--xy-controls-button-color-hover": tokens.text.primary,
    "--xy-controls-button-border-color": tokens.border.default,
  } as const;
  // The custom-property keys are intentionally not part of the standard
  // CSSProperties index; the cast keeps the public React Flow API typed.
  return variables as unknown as CSSProperties;
}

/**
 * The render-boundary endpoint invariant (PR 35-1 amendment 1 Part 6).
 *
 * A relationship edge may reach the canvas only when BOTH endpoints exist in
 * the canonical model AND are present in the final rendered React Flow node
 * set. Canonical edges are never deleted: only this rendering projection is
 * filtered, so an edge whose endpoint is temporarily absent (bounded depth,
 * filter, truncation, or transient reconciliation) can never draw a dangling
 * line.
 */
export function selectRenderableEdges(
  edges: readonly RelationshipGraphEdge[],
  canonicalEntityIds: ReadonlySet<string>,
  renderedEntityIds: ReadonlySet<string>,
): RelationshipGraphEdge[] {
  return edges.filter(
    (edge) =>
      canonicalEntityIds.has(edge.sourceEntityId) &&
      canonicalEntityIds.has(edge.targetEntityId) &&
      renderedEntityIds.has(edge.sourceEntityId) &&
      renderedEntityIds.has(edge.targetEntityId),
  );
}

/**
 * Map every canonical Relationship to one explicitly routed React Flow edge.
 *
 * One canonical Relationship stays one edge. Edges sharing an endpoint pair
 * (parallel Relationships, or a canonical self-loop) are separated through
 * deterministic handle slots so every path is visibly rendered and each
 * edge keeps an exact source/target node; slot 0 is the historical center
 * route. A self-loop routes between distinct same-node handles so it draws a
 * visible arc instead of a zero-length path. The deterministic arrow marker
 * communicates direction without alternate topology. PR 31I adds an optional
 * path highlight: relationships on the highlighted path get the emphasized
 * color and a thicker stroke while non-participating relationships in the
 * returned path topology are dimmed.
 */
export function buildSlottedEdges(
  edges: readonly RelationshipGraphEdge[],
  typeLabel: (type: string) => string,
  /** Semantic edge-stroke/arrow color from the active theme (PR 31F-4). */
  markerColor: string,
  highlight?: {
    highlightedRelationshipIds: ReadonlySet<string> | null;
    highlightedColor: string;
    dimmedColor: string;
    dimmedOpacity: number;
  },
): Edge[] {
  const groups = new Map<string, RelationshipGraphEdge[]>();
  for (const edge of edges) {
    const key =
      edge.sourceEntityId === edge.targetEntityId
        ? `self:${edge.sourceEntityId}`
        : [edge.sourceEntityId, edge.targetEntityId].sort().join("|");
    const list = groups.get(key) ?? [];
    list.push(edge);
    groups.set(key, list);
  }
  const result: Edge[] = [];
  const highlightActive =
    highlight !== undefined && highlight.highlightedRelationshipIds !== null;
  const strokeColorFor = (edge: RelationshipGraphEdge): string => {
    if (highlight === undefined) {
      return markerColor;
    }
    if (highlight.highlightedRelationshipIds?.has(edge.relationshipId)) {
      return highlight.highlightedColor;
    }
    return highlightActive ? highlight.dimmedColor : markerColor;
  };
  const strokeWidthFor = (edge: RelationshipGraphEdge): number =>
    highlight !== undefined &&
    highlight.highlightedRelationshipIds?.has(edge.relationshipId)
      ? 3
      : 1.5;
  const strokeOpacityFor = (edge: RelationshipGraphEdge): number =>
    highlightActive &&
    !highlight.highlightedRelationshipIds?.has(edge.relationshipId)
      ? highlight.dimmedOpacity
      : 1;
  for (const group of groups.values()) {
    const ordered = [...group].sort((a, b) =>
      a.relationshipId < b.relationshipId
        ? -1
        : a.relationshipId > b.relationshipId
          ? 1
          : 0,
    );
    ordered.forEach((edge, index) => {
      const knownOnly = edge.investigationObservationCount === 0;
      const knownOnlyStyle = knownOnly
        ? { strokeDasharray: "6 3" }
        : undefined;
      const stroke = strokeColorFor(edge);
      const pathStyle = {
        stroke,
        strokeWidth: strokeWidthFor(edge),
        strokeOpacity: strokeOpacityFor(edge),
      };
      if (edge.sourceEntityId === edge.targetEntityId) {
        result.push({
          id: edgeId(edge.relationshipId),
          source: nodeId(edge.sourceEntityId),
          target: nodeId(edge.targetEntityId),
          sourceHandle: "source-loop",
          targetHandle: "target-loop",
          label: typeLabel(edge.relationshipType),
          type: "default",
          style: { ...knownOnlyStyle, ...pathStyle },
          markerEnd: { type: MarkerType.ArrowClosed, color: stroke },
        });
        return;
      }
      const slot = index % 3;
      result.push({
        id: edgeId(edge.relationshipId),
        source: nodeId(edge.sourceEntityId),
        target: nodeId(edge.targetEntityId),
        sourceHandle: slot === 0 ? "source-bottom-0" : slot === 1 ? "source-bottom-1" : "source-bottom-2",
        targetHandle: slot === 0 ? "target-top-0" : slot === 1 ? "target-top-1" : "target-top-2",
        label: typeLabel(edge.relationshipType),
        type: "default",
        style: { ...knownOnlyStyle, ...pathStyle },
        markerEnd: { type: MarkerType.ArrowClosed, color: stroke },
      });
    });
  }
  return result;
}

/** Fallback compact graph label when a node is not on the page. */
function graphLabel(entityId: string): string {
  return `Entity ${entityId.slice(0, 8)}`;
}

/** Whether an edge is supported by the current Investigation (backend truth). */
function edgeSupported(edge: RelationshipGraphEdge): boolean {
  return edge.investigationObservationCount > 0;
}

/** The deterministic Investigation/Known context cue for one edge. */
function edgeContextLabel(t: TFunction, edge: RelationshipGraphEdge): string {
  return edgeSupported(edge)
    ? t("graph.context.supported")
    : t("graph.context.knownOnly");
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
  entityTypeLabel,
  drillDownState,
  onInspectObservations,
}: {
  t: TFunction;
  investigationId: string;
  focalEntityId: string;
  model: RelationshipGraphModel;
  nodeById: Map<string, RelationshipGraphNode>;
  typeLabel: (type: string) => string;
  entityTypeLabel: (type: string) => string;
  /** Transient bounded navigation context carried to Relationship history. */
  drillDownState: unknown;
  /** PR 31F: open the graph-local provenance panel for one canonical edge. */
  onInspectObservations: (relationshipId: string) => void;
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
              { label: t("graph.list.type") },
              { label: t("graph.list.source") },
              { label: t("graph.list.target") },
              { label: t("graph.list.supportingObservations"), tooltip: t("graph.list.supportingObservationsTooltip") },
              { label: t("graph.list.matchingInThisInvestigation"), tooltip: t("graph.list.matchingInThisInvestigationTooltip") },
              { label: t("graph.list.firstObserved") },
              { label: t("graph.list.lastObserved") },
              { label: t("graph.list.action") },
            ].map(({ label, tooltip }) => (
              <th key={label} scope="col" style={{ textAlign: "left", padding: 6 }}>
                {tooltip === undefined ? label : (
                  <Tooltip title={tooltip}>
                    <Box component="span" sx={{ cursor: "help" }}>{label}</Box>
                  </Tooltip>
                )}
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
                    <Box component="span">{source !== undefined ? `${entityTypeLabel(source.entityType)} ${source.value}` : graphLabel(edge.sourceEntityId)}</Box>
                    <CompactId id={edge.sourceEntityId} label={t("graph.detail.entityId")} />
                  </Box>
                </td>
                <td style={{ padding: 6 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <Box component="span">{target !== undefined ? `${entityTypeLabel(target.entityType)} ${target.value}` : graphLabel(edge.targetEntityId)}</Box>
                    <CompactId id={edge.targetEntityId} label={t("graph.detail.entityId")} />
                  </Box>
                </td>
                <td style={{ padding: 6 }}>{String(edge.observationCount)}</td>
                <td style={{ padding: 6 }}>{String(edge.investigationObservationCount)}</td>
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
                <td style={{ padding: 6, textAlign: "left" }}>
                  <Box sx={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 0.5 }}>
                  <Link
                    href={`/investigations/${investigationId}/relationships?selected=${edge.relationshipId}`}
                    underline="hover"
                    sx={{ fontSize: "inherit" }}
                  >
                    {t("graph.list.view")}
                  </Link>
                  <Link
                    component={RouterLink}
                    to={evolutionLink(investigationId, counterpartyId)}
                    state={drillDownState}
                    underline="hover"
                    sx={{ fontSize: "inherit" }}
                  >
                    {t("graph.list.viewEvolution")}
                  </Link>
                  <Link
                    href={`#relationship-provenance-${edge.relationshipId}`}
                    underline="hover"
                    sx={{ fontSize: "inherit" }}
                    onClick={(event) => {
                      event.preventDefault();
                      onInspectObservations(edge.relationshipId);
                    }}
                  >
                    {t("graph.provenance.inspect")}
                  </Link>
                  </Box>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Box>
  );
}
