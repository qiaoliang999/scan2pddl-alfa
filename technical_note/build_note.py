from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import ListFlowable, ListItem, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = REPO_ROOT / "technical_note" / "scan2pddl_alfa_technical_note.pdf"


def build_pdf() -> Path:
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=19,
        leading=23,
        spaceAfter=10,
        textColor=colors.HexColor("#12344d"),
    )
    subtitle = ParagraphStyle(
        "Subtitle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#4b5d6b"),
        spaceAfter=12,
    )
    heading = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=14,
        textColor=colors.HexColor("#12344d"),
        spaceBefore=4,
        spaceAfter=5,
    )
    body = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=12.5,
        spaceAfter=6,
    )
    small = ParagraphStyle(
        "Small",
        parent=body,
        fontSize=8.5,
        leading=10.5,
        textColor=colors.HexColor("#52606d"),
    )

    doc = SimpleDocTemplate(
        str(OUTPUT_PATH),
        pagesize=letter,
        leftMargin=0.68 * inch,
        rightMargin=0.68 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.62 * inch,
        title="Scan2PDDL-ALFA Technical Note",
        author="Qiao Liang",
    )

    story = [
        Paragraph("Scan2PDDL-ALFA", title),
        Paragraph(
            "A prototype for converting scan-derived host and service information into "
            "ALFA-Chains-style PDDL problem files.",
            subtitle,
        ),
    ]

    story.extend(
        [
            Paragraph("Problem", heading),
            Paragraph(
                "The 2025 ALFA-Chains preprint, <i>Hybrid Privilege Escalation and "
                "Remote Code Execution Exploit Chains</i>, identifies network modeling "
                "as a practical bottleneck in exploit-chain discovery. The planner "
                "depends on a PDDL problem file that describes hosts, products, "
                "versions, service exposure, and network topology. In the paper this "
                "problem file is prepared manually, and the authors explicitly note "
                "that incomplete or ambiguous network descriptions can hinder the "
                "discovery of exploit chains.",
                body,
            ),
            Paragraph(
                "The paper also points to a natural next step: integrate network "
                "scanning tools to extract host and service information and assist in "
                "producing the problem files. Scan2PDDL-ALFA explores one adjacent "
                "automation step in that direction.",
                body,
            ),
            Paragraph("Contribution", heading),
            Paragraph(
                "Scan2PDDL-ALFA is a research-engineering prototype that translates "
                "network scan outputs into ALFA-Chains-style PDDL problem files. The "
                "current implementation supports Nmap XML, a normalized JSON "
                "inventory format, and an optional overlay file for analyst-supplied "
                "topology semantics such as logical subnets, attacker entry network, "
                "and multi-homed hosts.",
                body,
            ),
        ]
    )

    bullet_items = [
        "parse hosts, service fingerprints, operating-system hints, and CPE strings",
        "normalize products into ALFA-style product tokens",
        "split versions into major, minor, and patch objects",
        "emit predicates such as connected_to_network, has_product, has_version, TCP_listen, UDP_listen, and is_compromised",
        "preserve a clear boundary between observed scan facts and analyst-provided topology intent",
    ]
    story.append(
        ListFlowable(
            [ListItem(Paragraph(item, body), leftIndent=8) for item in bullet_items],
            bulletType="bullet",
            start="circle",
            leftIndent=14,
        )
    )
    story.append(Spacer(1, 0.08 * inch))

    story.extend(
        [
            Paragraph("Design", heading),
            Paragraph(
                "The design is intentionally conservative. Nmap can often observe host "
                "addresses, hostnames, service fingerprints, and product-version "
                "hints, but it cannot reliably reconstruct semantic labels such as "
                "<i>dmz</i> or <i>lan</i>, nor can it infer the analyst's intended "
                "target host. For that reason, the tool supports a lightweight "
                "overlay JSON file rather than pretending the scan can recover all of "
                "the topology semantics by itself.",
                body,
            ),
        ]
    )

    table = Table(
        [
            ["Input layer", "Output layer"],
            ["Nmap XML / JSON inventory", "ALFA-Chains-style PDDL problem file"],
            ["Observed hosts and services", "Host objects and configuration predicates"],
            ["CPEs and version strings", "Product and version objects"],
            ["Overlay topology semantics", "connected_to_network and goal state"],
        ],
        colWidths=[2.4 * inch, 3.6 * inch],
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dcebf7")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#12344d")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.7),
                ("LEADING", (0, 0), (-1, -1), 10.4),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b9c9d6")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend([table, Spacer(1, 0.12 * inch)])

    story.extend(
        [
            Paragraph("Validation", heading),
            Paragraph(
                "The repository includes a motivating-example scan and overlay pair "
                "that reconstruct the paper's DMZ-LAN scenario at the problem-file "
                "level. The generated PDDL expresses an external attacker in the dmz, "
                "a web server reachable from both dmz and lan, and a database server "
                "reachable from the lan. The resulting problem file contains the "
                "expected software predicates for Drupal 8.6.9, PHP 7.0.33, Ubuntu "
                "Linux 16.04, Apache CouchDB 2.0.0, and Linux Kernel 4.8.0.",
                body,
            ),
            Paragraph(
                "Automated tests cover both Nmap XML and normalized JSON flows to "
                "ensure the generated predicate structure is stable. This is evidence "
                "of paper-level structural alignment, not verified compatibility with "
                "the authors' internal ALFA-Chains implementation.",
                body,
            ),
            PageBreak(),
            Paragraph("Limitations", heading),
            Paragraph(
                "This prototype does not yet generate the ALFA-Chains domain file, "
                "query BRON for exploit relevance, or run a planner end-to-end. It "
                "should therefore be understood as a building block rather than a "
                "complete exploit-chain discovery system. The most natural extension "
                "is to connect the generated product-version tuples to BRON or a "
                "similar knowledge layer, filter the relevant exploits, and assemble "
                "a constrained domain file automatically.",
                body,
            ),
            Paragraph("Why The Overlay Matters", heading),
            Paragraph(
                "The overlay mechanism is deliberate rather than cosmetic. Scanners "
                "can observe hosts, services, and some product-version hints, but "
                "they generally cannot recover analyst-defined topology semantics "
                "such as dmz, lan, or the intended attacker entry point. The overlay "
                "keeps the model honest by separating scan-derived facts from "
                "operator-supplied topology intent.",
                body,
            ),
            Paragraph("Next Research Step", heading),
            Paragraph(
                "A natural extension is to connect the generated product-version "
                "tuples to BRON or a similar knowledge layer, filter exploits that "
                "are relevant to the observed hosts, and then generate a constrained "
                "PDDL domain file. That would move this work from scan-assisted "
                "problem modeling toward a more complete ALFA-Chains pipeline.",
                body,
            ),
            ListFlowable(
                [
                    ListItem(Paragraph("query BRON using normalized product-version tuples", body), leftIndent=8),
                    ListItem(Paragraph("select only exploits relevant to observed hosts", body), leftIndent=8),
                    ListItem(Paragraph("generate a constrained domain file automatically", body), leftIndent=8),
                    ListItem(Paragraph("test planner compatibility on motivating and larger benchmark networks", body), leftIndent=8),
                ],
                bulletType="bullet",
                start="circle",
                leftIndent=14,
            ),
            Spacer(1, 0.08 * inch),
            Paragraph(
                "Reference: Hemberg et al., <i>Hybrid Privilege Escalation and Remote "
                "Code Execution Exploit Chains</i>, 2025 preprint.",
                small,
            ),
        ]
    )

    doc.build(story)
    return OUTPUT_PATH


if __name__ == "__main__":
    path = build_pdf()
    print(path)
