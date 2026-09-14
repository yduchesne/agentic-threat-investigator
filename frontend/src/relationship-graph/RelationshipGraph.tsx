// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Bounded one-hop stable Relationship graph (PR 24E §21-§29).
//
// React Flow (@xyflow/react) renders only already-known stable
// Relationships of one bounded Relationships page for one focal entity: it
// is a navigation aid, never a discovery or inference engine. Nodes and
// edges are backed by exact Entity/Relationship IDs; deterministic radial
// layout is presentation only and never persisted. The accessible
// non-spatial alternative (an edge list with exact navigation links) is
// always rendered, so canvas exploration is never required to reach data.

import { Alert, Box, Button, Link, Typography } from "@mui/material";
import {
  Background,
  Controls,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { ReactElement } from "react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";

import type { Relationship } from "../api/schema-types";
import { CompactId } from "../components/CompactId";
import { PivotMenu } from "../pivots/PivotMenu";
import { entityActions } from "../pivots/pivot-capabilities";
import { relationshipObservationsAction } from "../pivots/pivot-capabilities";
import type { RelationshipGraphModel } from "./relationship-graph-model";
import { radialPositions, layoutSize } from "./relationship-graph-layout";

/** One custom React Flow node backed by an exact Entity ID. */
export type EvolutionNodeData = {
  label: string;
  role: "focal" | "counterparty";
} & Record<string, unknown>;

const nodeTypes: NodeTypes = { evolutionNode: EvolutionGraphNode };

function EvolutionGraphNode({ data }: NodeProps): ReactElement {
  const nodeData = data as EvolutionNodeData;
  return (
    <Box
      sx={{
        px: 1.25,
        py: 0.5,
        border: 2,
        borderRadius: 999,
        borderColor: nodeData.role === "focal" ? "primary.main" : "divider",
        bgcolor: nodeData.role === "focal" ? "primary.main" : "background.paper",
        color: nodeData.role === "focal" ? "primary.contrastText" : "text.primary",
        fontSize: 12,
        fontFamily: "monospace",
        whiteSpace: "nowrap",
      }}
    >
      {nodeData.label}
    </Box>
  );
}

export interface RelationshipGraphProps {
  investigationId: string;
  focalEntityId: string;
  model: RelationshipGraphModel;
  /** Raw bounded page rows (edge-list alternative renders the same page). */
  rows: readonly Relationship[];
  hasNext: boolean;
  typeLabel: (type: string) => string;
}

/** The bounded one-hop graph surface with an always-available list path. */
export function RelationshipGraph({
  investigationId,
  focalEntityId,
  model,
  rows,
  hasNext,
  typeLabel,
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

  const nodes: Node<EvolutionNodeData>[] = useMemo(() => {
    const all: Array<Node<EvolutionNodeData>> = [
      {
        id: nodeId(model.focal.entityId),
        type: "evolutionNode",
        position: positions.focal,
        data: { label: model.focal.label, role: "focal" },
      },
      ...model.counterparties.map((node) => ({
        id: nodeId(node.entityId),
        type: "evolutionNode" as const,
        position: positions.counterparties.get(node.entityId) ?? { x: 0, y: 0 },
        data: { label: node.label, role: node.role },
      })),
    ];
    return all;
  }, [model, positions]);

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

  const selectedEdge = useMemo(
    () =>
      selection?.kind === "edge"
        ? model.edges.find((edge) => edge.relationshipId === selection.edgeId) ?? null
        : null,
    [selection, model.edges],
  );

  const selectedNode = useMemo(() => {
    if (selection?.kind !== "node") {
      return null;
    }
    const id = entityIdFromNodeId(selection.nodeId);
    if (id === null) {
      return null;
    }
    return {
      entityId: id,
      label:
        id === model.focal.entityId
          ? model.focal.label
          : model.counterparties.find((node) => node.entityId === id)?.label ??
            graphLabel(id),
    };
  }, [selection, model]);

  return (
    <Box>
      {hasNext ? (
        <Alert severity="info" role="status" sx={{ mb: 1 }}>
          {t("graph.boundedNotice")}
        </Alert>
      ) : null}
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
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
          minZoom={0.25}
          maxZoom={2}
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
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 0.5 }}>
            <PivotMenu
              actions={entityActions(selectedNode.entityId, selectedNode.label, "detail_field")}
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
          rows={rows}
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

/** Fallback compact graph label. */
function graphLabel(entityId: string): string {
  return `Entity ${entityId.slice(0, 8)}`;
}

/** The evolution route link for one entity. */
export function evolutionLink(investigationId: string, entityId: string): string {
  return `/investigations/${investigationId}/relationships/evolution?entity_id=${entityId}`;
}

/** Edge-list navigation table (the always-loaded accessible alternative). */
function EdgeList({
  t,
  investigationId,
  focalEntityId,
  rows,
  typeLabel,
}: {
  t: TFunction;
  investigationId: string;
  focalEntityId: string;
  rows: readonly Relationship[];
  typeLabel: (type: string) => string;
}): ReactElement {
  return (
    <Box sx={{ overflowX: "auto" }}>
      <table aria-label={t("graph.listHeading")} style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead>
          <tr>
            {[
              t("graph.list.type"),
              t("graph.list.direction"),
              t("graph.list.counterparty"),
              t("graph.list.relationship"),
              t("graph.list.evolution"),
            ].map((header) => (
              <th key={header} scope="col" style={{ textAlign: "left", padding: 6 }}>
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((relationship) => (
            <tr key={relationship.id}>
              <td style={{ padding: 6 }}>{typeLabel(relationship.type)}</td>
              <td style={{ padding: 6 }}>
                {relationship.target_entity_id === focalEntityId
                  ? t("graph.list.inbound")
                  : relationship.source_entity_id === focalEntityId
                    ? t("graph.list.outbound")
                    : t("graph.list.either")}
              </td>
              <td style={{ padding: 6 }}>
                <CompactId
                  id={
                    relationship.source_entity_id === focalEntityId
                      ? relationship.target_entity_id
                      : relationship.source_entity_id
                  }
                  label={t("graph.list.counterparty")}
                />
              </td>
              <td style={{ padding: 6 }}>
                <Button
                  size="small"
                  component="a"
                  href={`/investigations/${investigationId}/relationships?selected=${relationship.id}`}
                  sx={{ textTransform: "none" }}
                >
                  {t("graph.list.view")}
                </Button>
              </td>
              <td style={{ padding: 6 }}>
                <Button
                  size="small"
                  component="a"
                  href={evolutionLink(
                    investigationId,
                    relationship.source_entity_id === focalEntityId
                      ? relationship.target_entity_id
                      : relationship.source_entity_id,
                  )}
                  sx={{ textTransform: "none" }}
                >
                  {t("graph.list.viewEvolution")}
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Box>
  );
}