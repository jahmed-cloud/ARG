# Microsoft Azure architecture icons

The SVG files in this folder are unmodified copies of icons from Microsoft's **Azure Public Service Icons V24**
(downloaded 2026-10-06 from <https://learn.microsoft.com/azure/architecture/icons/>). They are Microsoft's, not
part of ARG's MIT-licensed code, and are used only as Microsoft allows: in architecture diagrams - the
architecture views (`scripts/subscription_analysis/diagram.py`, `network_diagram.py`) and the Policy page's assignment
tree (management group, subscription, resource group and Azure Policy icons, served unchanged at `/azure-icons/` by the
local portal; the Docker UI ships the same four files in `frontend/public/azure-icons/`).

Rules from Microsoft's icon FAQ that the diagrams and the assignment tree follow:

- an icon only represents the Azure service it was designed for (`diagram_icons.py` maps resource types to them);
- icons are not cropped, flipped, rotated, recoloured or distorted - they are embedded byte for byte and only scaled;
- the full service name is shown next to every icon.

Only the icons the diagrams use are kept. To refresh them, download the current pack from the page above and copy the
files named in `diagram_icons.py` (pack file name without the `<number>-icon-service-` prefix).
