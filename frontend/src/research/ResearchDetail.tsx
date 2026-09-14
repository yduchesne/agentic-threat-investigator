// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// ResearchResult detail surface (PR 24C §10).
//
// Research is contextual knowledge, never Evidence: the page says
// ``Research context`` and the detail renders metadata, structured claims
// with their citation references, and the persisted citations themselves.
// Claim-to-citation closure is inspectable by citation id. External
// research text is untrusted data — React-escaping only, no raw HTML, no
// browser source fetching. Retrieval similarity is never labeled
// credibility/truth/maliciousness/confidence.

import { Box, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type { ResearchCitation, ResearchResult } from "../api/schema-types";
import { CompactId } from "../components/CompactId";
import { SafeExternalLink } from "../components/SafeExternalLink";
import { Timestamp } from "../components/Timestamp";
import { DetailRows, DetailSection } from "../analyst-table/DetailRows";
import { PivotMenu } from "../pivots/PivotMenu";
import { researchSubjectActions } from "../pivots/pivot-capabilities";

/** One metadata + claims + citations detail surface. */
export function ResearchDetail({ research }: { research: ResearchResult }): ReactElement {
  const { t } = useTranslation("research");
  const { t: tPivots } = useTranslation("pivots");
  const citationsById = new Map(research.citations.map((citation) => [citation.citation_id, citation]));

  return (
    <Box>
      <DetailRows
        rows={[
          { label: t("detail.query"), value: research.query },
          {
            label: t("detail.subjectEntity"),
            value: <CompactId id={research.subject_entity_id} label={t("detail.subjectEntity")} />,
          },
          { label: t("detail.createdAt"), value: <Timestamp iso={research.created_at} /> },
          {
            label: t("detail.resultId"),
            value: <CompactId id={research.id} label={t("detail.resultId")} />,
          },
        ]}
      />
      <DetailSection title={tPivots("detail.pivot.title")}>
        <PivotMenu
          actions={researchSubjectActions(research, "detail_field")}
          ariaLabel={tPivots("detail.pivot.aria")}
        />
      </DetailSection>
      <DetailSection title={t("detail.claims.title")}>
        {research.claims.length === 0 ? (
          <Typography variant="body2">{t("detail.claims.none")}</Typography>
        ) : (
          <Box>
            {research.claims.map((claim) => (
              <Box
                key={claim.id}
                role="listitem"
                sx={(theme) => ({
                  p: 1,
                  mb: 1,
                  borderRadius: 0.5,
                  border: 1,
                  borderColor: theme.palette.divider,
                })}
              >
                <Typography variant="body2">{claim.text}</Typography>
                <Box sx={{ mt: 0.5 }}>
                  {claim.citation_ids.length === 0 ? (
                    <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>
                      {t("detail.claims.noCitations")}
                    </Typography>
                  ) : (
                    <Box role="list" aria-label={t("detail.claims.citations")}>
                      {claim.citation_ids.map((citationId) => {
                        const citation = citationsById.get(citationId);
                        return (
                          <Box key={citationId} role="listitem">
                            <Typography variant="caption" sx={{ display: "block" }}>
                              {t("detail.claims.citationFor", { id: shortCitation(citationId) })}
                              {citation !== undefined ? ` — ${citation.title ?? citation.source_id}` : ""}
                            </Typography>
                            {citation !== undefined ? (
                              <Typography
                                variant="caption"
                                component="span"
                                sx={{ display: "block", fontFamily: "monospace", wordBreak: "break-all" }}
                              >
                                <SafeExternalLink url={citation.source_url} ariaLabel={t("detail.citations.sourceUrl")} />
                              </Typography>
                            ) : null}
                          </Box>
                        );
                      })}
                    </Box>
                  )}
                </Box>
              </Box>
            ))}
          </Box>
        )}
      </DetailSection>
      <DetailSection title={t("detail.citations.title")}>
        {research.citations.length === 0 ? (
          <Typography variant="body2">{t("detail.citations.none")}</Typography>
        ) : (
          research.citations.map((citation) => <CitationBlock key={citation.citation_id} citation={citation} />)
        )}
      </DetailSection>
    </Box>
  );
}

/** One persisted citation/source metadata block. */
function CitationBlock({ citation }: { citation: ResearchCitation }): ReactElement {
  const { t } = useTranslation("research");
  return (
    <Box
      role="listitem"
      sx={(theme) => ({
        p: 1,
        mb: 1,
        borderRadius: 0.5,
        border: 1,
        borderColor: theme.palette.divider,
      })}
    >
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        {citation.title ?? shortCitation(citation.citation_id)}
      </Typography>
      <DetailRows
        rows={[
          { label: t("detail.citations.sourceId"), value: citation.source_id },
          { label: t("detail.citations.sourceRecordId"), value: citation.source_record_id },
          {
            label: t("detail.citations.publishedAt"),
            value: citation.published_at !== null ? <Timestamp iso={citation.published_at} /> : t("detail.citations.nullable"),
          },
          {
            label: t("detail.citations.chunkSequence"),
            value: String(citation.chunk_sequence),
          },
          {
            label: t("detail.citations.similarity"),
            value: citation.similarity_score !== null ? String(citation.similarity_score) : t("detail.citations.nullable"),
          },
          {
            label: t("detail.citations.documentType"),
            value: citation.document_type,
          },
          {
            label: t("detail.citations.citationId"),
            value: <CompactId id={citation.citation_id} label={t("detail.citations.citationId")} />,
          },
        ]}
      />
      <Box sx={{ mt: 0.5 }}>
        <Typography variant="body2" sx={(theme) => ({ fontStyle: "italic", color: theme.palette.text.secondary })}>
          {citation.text}
        </Typography>
      </Box>
      <Box sx={{ mt: 0.5 }}>
        <SafeExternalLink url={citation.source_url} label={t("detail.citations.sourceUrl")} />
      </Box>
    </Box>
  );
}

/** Compact citation reference (never decoded). */
function shortCitation(citationId: string): string {
  return citationId.slice(0, 8);
}