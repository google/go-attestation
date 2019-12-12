# Verifying TPM Boot Events and Untrusted Metadata

This is a disclosure of a vulnerability report sent to the Trusted Computing Group.

## TPM boot logs

TPMs are cryptographic hardware that, among other things, can be used to verify the boot state of a machine; that a machine booted a specific OS, enabled specific BIOS settings, and hasn’t had its bootchain tampered with.

As a machine boots it records events, such as the bootloader hash and secure boot keys, in a structure called the Event Log. When an event is written to the log, its digest is also written to rolling hashes in the TPM called PCRs. PCR values can be attested remotely by the TPM and used to verify the log by replaying the log’s digests. If the replay matches the PCRs’ values the log hasn’t been tampered with.

An Event Log is a series of events using the following format (the TPM 2.0 format is slightly different but functionally the same):

```
typedef struct tdTCG_PCR_EVENT {
    TCG_PCRINDEX  PCRIndex;         // PCRIndex event extended to
    TCG_EVENTTYPE EventType;        // Type of event (see EFI specs)
    TCG_DIGEST    Digest;           // Value extended into PCRIndex
    UINT32        EventSize;        // Size of the event data
    UINT8         Event[EventSize]; // The event data
} TCG_PCR_EVENT;	

typedef UINT32 TCG_PCRINDEX;
typedef UINT32 TCG_EVENTTYPE;
typedef UINT8  TCG_DIGEST[20];
```

\- [_TCG EFI Protocol Specification 5.1_][efi-spec-5_1]

PCRIndex indicates which PCR was extended. The Digest is the value written to the PCR and is a hash of the Event.* EventType indicates what kind of data is being conveyed.

<sub>* Except when the Digest is the value being communicated (the bootloader hash) or a hash of part of the event (some UEFI variables).</sub>

[efi-spec-5_1]: https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15

## Event type and verification footguns

To verify a machine’s state, it might seem reasonable to parse the Event Log, replay the Digests against the PCRs to verify it hasn’t been tampered with, then parse data from the log to get things like a machine’s secure boot settings.

This is wrong.

Replaying an Event Log only verifies a subset of the fields in an Event. Specifically, it only guarantees PCRIndex, Digest, and sometimes the event data, but __the EventType isn’t part of the Digest and can be freely modified by an attacker.__

Consider the following event log for secure boot entries (PCR[7]):

```
PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=53
PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=842
PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=1598
PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=4744
PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=3762
PCRIndex=7 EventType=EV_SEPARATOR EventSize=4
PCRIndex=7 EventType=EV_EFI_VARIABLE_AUTHORITY EventSize=1573
```

To determine the secure boot state of a device, a parser might reasonably implement the following logic after verifying an event log:

```
for (event in events) {
    switch (event.type) {
        case EV_EFI_VARIABLE_AUTHORITY:
            // Parse EFI variable for secure boot state
            // ...
        case EV_EFI_VARIABLE_DRIVER_CONFIG:
            // ...
        case EV_SEPARATOR:
            // ...
        case /* more cases */:
            // ...
        default:
            // Ignore unknown event types
            continue;
    }
}
```

Because of the “default” condition, an attacker can change all existing event log types to a type the parser doesn’t interpret, for example the reserved type EV_UNUSED, then append their own events and extend the PCRs:

```diff
-PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=53
-PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=842
-PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=1598
-PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=4744
-PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=3762
-PCRIndex=7 EventType=EV_SEPARATOR EventSize=4
-PCRIndex=7 EventType=EV_EFI_VARIABLE_AUTHORITY EventSize=1573
+PCRIndex=7 EventType=EV_UNUSED EventSize=53
+PCRIndex=7 EventType=EV_UNUSED EventSize=842
+PCRIndex=7 EventType=EV_UNUSED EventSize=1598
+PCRIndex=7 EventType=EV_UNUSED EventSize=4744
+PCRIndex=7 EventType=EV_UNUSED EventSize=3762
+PCRIndex=7 EventType=EV_UNUSED EventSize=4
+PCRIndex=7 EventType=EV_UNUSED EventSize=1573
+PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=53
+PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=842
+PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=1598
+PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=4744
+PCRIndex=7 EventType=EV_EFI_VARIABLE_DRIVER_CONFIG EventSize=3762
+PCRIndex=7 EventType=EV_SEPARATOR EventSize=4
+PCRIndex=7 EventType=EV_EFI_VARIABLE_AUTHORITY EventSize=1573
```

The PCR replay and TPM quote will match this event log, but the parser will skip over the legitimate values and use attacker supplied ones.

Even if the parser exhaustively matches event types, an attacker can masquerade a required event as an optional one in hopes the parser will no-op. For example, consider the following bootloader entries (PCR [4]):

```
PCRIndex=4 EventType=EV_SEPARATOR EventSize=4
PCRIndex=4 EventType=EV_EFI_BOOT_SERVICES_APPLICATION EventSize=158
```

In this case, an attacker can change the bootloader hash event type to an optional event type, then append their own hash. This is especially hard to detect because the Digest of EV_EFI_PLATFORM_FIRMWARE_BLOB and EV_EFI_BOOT_SERVICES_APPLICATION event types aren’t a hash of their event data, so an attacker can also modify the data to match the parser’s expectations too:

```diff
PCRIndex=4 EventType=EV_SEPARATOR EventSize=4
-PCRIndex=4 EventType=EV_EFI_BOOT_SERVICES_APPLICATION EventSize=158
+PCRIndex=4 EventType=EV_EFI_PLATFORM_FIRMWARE_BLOB EventSize=124
+PCRIndex=4 EventType=EV_EFI_BOOT_SERVICES_APPLICATION EventSize=158
```

## Vulnerability report and outcome

This issue was reported to the Trusted Computing Group on September 6th and eventually triaged by their Vulnerability Response Team.

At the time of the report, there was no conical recommendations for how to verify an Event Log and there was no warning in the [Event Log spec][spec-event-logging] that fields are untrusted. The TCG noted that event data is meant for debugging, and that event digests (the values written to the PCRs) are the only fields that should be used for trust decisions. The TCG confirmed that guidance for verifying the Event Log is being drafted. Updated specifications, including a new document, the TCG Firmware Integrity Measurement Specification, have been [released for public review][spec-public-review].The guidance document will be available soon at the same location.

The full 90-day disclosure deadline was requested to determine if other TCG members were vulnerable to this issue.

This issue is a nice reminder that mixing trusted and untrusted data is a recipe for [implementation][saml-sig-wrapping] [vulnerabilities][jwt-header-none]. We plan to update our open source project [go-attestation][go-attestation] to better help users identify what can be used for trust decisions and what’s reserved for debugging.

A special thanks to Amy Nelson, the PC Client Workgroup Chair, for being our point of contact through this process.

[spec-event-logging]: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=90
[spec-event-logging-draft]: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_05_3feb20.pdf#page=89
[spec-public-review]: https://trustedcomputinggroup.org/specifications-public-review/
[saml-sig-wrapping]: https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf
[jwt-header-none]: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
[go-attestation]: https://github.com/google/go-attestation
