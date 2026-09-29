// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Analyst Preferences dialog (PR 31F-4).
//
// A normal MUI Dialog — no route, no URL mutation and no navigation. The
// initial scope is exactly the Appearance preference: four
// human-readable choices with live preview, Save committing to local
// persistence, and Cancel/Escape restoring the committed appearance.
// Focus is trapped and restored by the MUI Dialog/Modal itself; all text
// is i18next-backed from the shell namespace. This dialog deliberately
// does not touch the custom Timeline DetailDrawer or any other existing
// surface.

import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Radio,
  RadioGroup,
  Typography,
} from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import { useAppearance } from "../app/AppearanceProvider";
import {
  APPEARANCE_PREFERENCES,
  isAppearancePreference,
  type AppearancePreference,
} from "../app/appearance";

/** i18n label lookup for the four bounded appearances. */
const APPEARANCE_LABEL_KEY: Record<AppearancePreference, string> = {
  light: "preferences.appearance.light",
  dark: "preferences.appearance.dark",
  wargames: "preferences.appearance.wargames",
  "control-room": "preferences.appearance.controlRoom",
};

export interface PreferencesDialogProps {
  open: boolean;
  /** Close request (Save/Cancel/Escape/backdrop). */
  onClose: () => void;
}

/** The Preferences modal: initial scope is Appearance only. */
export function PreferencesDialog({
  open,
  onClose,
}: PreferencesDialogProps): ReactElement {
  const { t } = useTranslation("shell");
  const {
    appearance,
    committed,
    previewAppearance,
    commitAppearance,
    cancelPreview,
  } = useAppearance();

  /** Any close gesture (Cancel, Escape, backdrop) discards the preview. */
  const handleCancel = (): void => {
    cancelPreview();
    onClose();
  };

  /** Save persists the previewed choice and closes. */
  const handleSave = (): void => {
    if (appearance !== committed) {
      commitAppearance();
    }
    onClose();
  };

  const radioGroupLabelId = "preferences-appearance-label";

  return (
    <Dialog
      open={open}
      onClose={handleCancel}
      fullWidth
      maxWidth="xs"
      aria-labelledby="preferences-dialog-title"
    >
      <DialogTitle id="preferences-dialog-title">{t("preferences.dialogTitle")}</DialogTitle>
      <DialogContent>
        <Typography
          id={radioGroupLabelId}
          variant="subtitle2"
          component="h2"
          sx={{ mt: 1 }}
        >
          {t("preferences.appearance.heading")}
        </Typography>
        <RadioGroup
          name="ati-appearance"
          aria-labelledby={radioGroupLabelId}
          value={appearance}
          onChange={(_event, value) => {
            if (isAppearancePreference(value)) {
              previewAppearance(value);
            }
          }}
        >
          {APPEARANCE_PREFERENCES.map((preference) => (
            <FormControlLabel
              key={preference}
              control={<Radio value={preference} />}
              label={t(APPEARANCE_LABEL_KEY[preference])}
            />
          ))}
        </RadioGroup>
      </DialogContent>
      <DialogActions>
        <Button size="small" onClick={handleCancel} sx={{ textTransform: "none" }}>
          {t("preferences.cancel")}
        </Button>
        <Button size="small" variant="contained" onClick={handleSave} sx={{ textTransform: "none" }}>
          {t("preferences.save")}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
