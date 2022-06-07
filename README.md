# uefivars

Utility for inspecting and managing a UEFI variable store firmware
volume, such as that used by The EDK II Project, and bhyve
in illumos.

```
% uefivars -l /zones/bloody/root/etc/uefivars
BOOT OPTIONS
------------
Bootorder: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
C H [0 ] UiApp - [App 462caa21-7614-4503-836e-8ab6f4662331]
    [1 ] UEFI Misc Device - [PCI 4.0]
    [2 ] UEFI Misc Device 2 - [PCI 5.0]
    [3 ] UEFI Misc Device 3 - [PCI 5.1]
    [4 ] UEFI Misc Device 4 - [PCI 5.2]
    [5 ] UEFI PXEv4 (MAC:020820101CB6) - [PCI 6.0]
    [6 ] UEFI HTTPv4 (MAC:020820101CB6) - [PCI 6.0] [HTTP]
    [7 ] UEFI PXEv4 (MAC:0208202240BF) - [PCI 6.2]
    [8 ] UEFI HTTPv4 (MAC:0208202240BF) - [PCI 6.2] [HTTP]
    [9 ] UEFI PXEv4 (MAC:0208208D7837) - [PCI 6.3]
    [10] UEFI HTTPv4 (MAC:0208208D7837) - [PCI 6.3] [HTTP]
    [11] EFI Internal Shell - [App 7c04a583-9e3e-4f1c-ad65-e05268d0b4d1]
C    - Current (first in boot order)
 N   - Next Boot
  H  - Hidden
```

