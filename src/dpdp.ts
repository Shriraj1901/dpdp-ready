/**
 * DPDP provisions referenced in findings. These point reviewers to the relevant text;
 * they are not legal conclusions. Wording kept short and neutral on purpose.
 */
export const DPDP = {
  security: "DPDP Act s.8(5): reasonable security safeguards to prevent a personal data breach",
  securityRule: "DPDP Rules 2025, Rule 6: security safeguards (e.g. encryption, masking, access control, logs)",
  breach: "DPDP Act s.8(6) and Rules 2025, Rule 7: personal data breach intimation",
  notice: "DPDP Act s.5 and Rules 2025, Rule 3: notice with an itemised description of personal data and purposes",
  consent: "DPDP Act s.6: consent must be free, specific, informed, unconditional and unambiguous",
  processor: "DPDP Act s.8(2): a Data Processor may process data only under a valid contract",
  transfer: "DPDP Act s.16: transfer of personal data outside India (subject to Government restrictions)",
  erasure: "DPDP Act s.8(7): erase personal data when the purpose is served or consent is withdrawn",
  minimisation: "DPDP Act s.6(1) and s.7: process only the personal data necessary for the specified purpose",
  children: "DPDP Act s.9 and Rules 2025, Rule 10: verifiable consent of a parent for children's data",
  rights: "DPDP Act ss.11–13: rights to access, correction, erasure and grievance redressal",
} as const;

export const DISCLAIMER =
  "This is an automated engineering scan, not a legal opinion or a compliance certificate. " +
  "Results show what the tool could detect in the files and pages it read. " +
  "Decisions about DPDP compliance must be reviewed by a qualified professional.";
