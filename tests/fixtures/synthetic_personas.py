"""Synthetic Resume Personas covering 15 diverse industries, professions, and career stages.

Strictly synthetic data — no personal identifying information of real candidates.
Provides helpers to generate genuine in-memory DOCX and PDF documents for testing.
"""

import io
from typing import Any, Dict, List
from docx import Document
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


PERSONA_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "backend_engineer": {
        "full_name": "Alex Mercer",
        "email": "alex.mercer@cloudinfra.io",
        "phone": "+1 (206) 555-0192",
        "location": "Seattle, WA, USA",
        "headline": "Staff Distributed Systems Engineer | 10+ Years Cloud Infrastructure",
        "summary": "Seasoned backend and distributed systems architect with a decade of experience designing fault-tolerant, high-throughput microservices using Go, Rust, and Kubernetes.",
        "education": [
            {
                "institution": "University of Washington",
                "degree": "Master of Science in Computer Science",
                "major": "Distributed Systems",
                "expected_graduation_year": 2014,
                "cgpa": 3.92,
            }
        ],
        "work_experience": [
            {
                "employer": "Apex Cloud Systems",
                "job_title": "Lead Backend Infrastructure Engineer",
                "duration": "48 months",
                "responsibilities": [
                    "Designed distributed consensus engine handling 2M requests/second.",
                    "Led cloud infrastructure migration to Kubernetes and service mesh.",
                ],
            }
        ],
        "skills": ["Go", "Rust", "Distributed Systems", "Kubernetes", "gRPC", "Kafka", "PostgreSQL", "Docker", "AWS"],
        "certifications": ["AWS Certified Solutions Architect – Professional", "Certified Kubernetes Administrator (CKA)"],
        "projects": [
            {
                "title": "High-Throughput Event Streaming Bus",
                "description": "Architected zero-copy pub/sub message bus in Rust reducing p99 latency by 45%.",
                "technologies": ["Rust", "Raft", "RocksDB"],
            }
        ],
    },
    "cardiologist": {
        "full_name": "Dr. Sarah Jenkins",
        "email": "dr.jenkins@bostonheartclinic.org",
        "phone": "+1 (617) 555-4812",
        "location": "Boston, MA, USA",
        "headline": "Board-Certified Cardiologist | Clinical Fellow in Interventional Cardiology",
        "summary": "Board-certified cardiologist with clinical fellowship training in adult echocardiography, catheterization, and coronary intervention across teaching hospital networks.",
        "education": [
            {
                "institution": "Harvard Medical School",
                "degree": "Doctor of Medicine (M.D.)",
                "major": "Cardiology",
                "expected_graduation_year": 2016,
                "cgpa": 3.95,
            }
        ],
        "work_experience": [
            {
                "employer": "Massachusetts General Hospital",
                "job_title": "Attending Cardiologist",
                "duration": "60 months",
                "responsibilities": [
                    "Managed inpatient cardiac telemetry unit and diagnostic catheterization lab.",
                    "Performed transesophageal echocardiograms and outpatient consultations.",
                ],
            }
        ],
        "skills": ["Echocardiography", "Cardiac Catheterization", "ECG Interpretation", "Heart Failure Management", "ACLS", "EPIC EMR"],
        "certifications": ["American Board of Internal Medicine – Cardiovascular Disease", "USMLE Step 1, 2 & 3"],
        "projects": [
            {
                "title": "Post-Myocardial Infarction Telemonitoring Protocol",
                "description": "Designed clinical trial workflow for continuous patient vitals monitoring via wearable ECG sensors.",
                "technologies": ["Clinical Research", "EPIC EMR", "Wearables"],
            }
        ],
    },
    "attorney": {
        "full_name": "Michael Vance",
        "email": "mvance@vancecorporate.com",
        "phone": "+1 (212) 555-9031",
        "location": "New York, NY, USA",
        "headline": "Senior Corporate Counsel | M&A and Cross-Border Transactions",
        "summary": "Corporate and transactional attorney specializing in venture financing, merger agreements, and SEC compliance for high-growth tech enterprises.",
        "education": [
            {
                "institution": "Columbia Law School",
                "degree": "Juris Doctor (J.D.)",
                "major": "Corporate Law",
                "expected_graduation_year": 2017,
                "cgpa": 3.85,
            }
        ],
        "work_experience": [
            {
                "employer": "Davis & Sterling LLP",
                "job_title": "Senior M&A Associate",
                "duration": "72 months",
                "responsibilities": [
                    "Structured multi-million dollar cross-border acquisitions and term sheets.",
                    "Drafted purchase agreements, disclosure schedules, and regulatory filings.",
                ],
            }
        ],
        "skills": ["Mergers & Acquisitions", "Corporate Governance", "Due Diligence", "Contract Drafting", "Securities Law", "Antitrust Compliance"],
        "certifications": ["New York State Bar Admission", "Delaware Bar Association Member"],
        "projects": [
            {
                "title": "Fintech Cross-Border Acquisition Filing",
                "description": "Led due diligence and Hart-Scott-Rodino regulatory clearance for $180M international buyout.",
                "technologies": ["LexisNexis", "DealRoom", "SEC EDGAR"],
            }
        ],
    },
    "cfa_investment_banker": {
        "full_name": "Priya Sharma",
        "email": "priya.sharma@mumbaicapital.in",
        "phone": "+91 98200 45678",
        "location": "Mumbai, Maharashtra, India",
        "headline": "Vice President | Investment Banking & Equity Research",
        "summary": "Chartered Financial Analyst with 8 years of sell-side equity research and debt restructuring advisory across Indian conglomerate markets.",
        "education": [
            {
                "institution": "Indian Institute of Management Ahmedabad",
                "degree": "Master of Business Administration (MBA)",
                "major": "Finance",
                "expected_graduation_year": 2018,
                "cgpa": 3.8,
            }
        ],
        "work_experience": [
            {
                "employer": "Kotak Mahindra Capital",
                "job_title": "Vice President – Investment Banking",
                "duration": "60 months",
                "responsibilities": [
                    "Led execution of 5 IPOs and QIP capital raises exceeding INR 4,500 Cr.",
                    "Constructed detailed three-statement financial models and DCF valuations.",
                ],
            }
        ],
        "skills": ["DCF Modeling", "LBO Valuation", "Equity Research", "Financial Due Diligence", "Bloomberg Terminal", "Pitch Books", "M&A Advisory"],
        "certifications": ["CFA Charterholder (CFA Institute)", "SEBI Registered Research Analyst"],
        "projects": [
            {
                "title": "Renewable Energy IPO Syndication",
                "description": "Structured book-building process and investor roadshows for INR 1,200 Cr solar energy public listing.",
                "technologies": ["Financial Modeling", "Bloomberg", "Excel"],
            }
        ],
    },
    "mechanical_engineer": {
        "full_name": "David Mueller",
        "email": "d.mueller@automotivetech.de",
        "phone": "+49 89 555 2104",
        "location": "Munich, Germany",
        "headline": "Senior Powertrain & Thermal Systems Engineer",
        "summary": "Mechanical design engineer with expertise in EV battery pack cooling, finite element analysis (FEA), and high-precision CAD modeling for automotive tier-1 suppliers.",
        "education": [
            {
                "institution": "Technical University of Munich",
                "degree": "Master of Science in Mechanical Engineering",
                "major": "Automotive Engineering",
                "expected_graduation_year": 2019,
                "cgpa": 3.85,
            }
        ],
        "work_experience": [
            {
                "employer": "Bavaria Mobility Systems",
                "job_title": "Thermal Simulation Lead",
                "duration": "50 months",
                "responsibilities": [
                    "Engineered liquid cooling plates for 800V high-capacity EV batteries.",
                    "Simulated thermal stress using ANSYS Fluent and OpenFOAM.",
                ],
            }
        ],
        "skills": ["SolidWorks", "CATIA V5", "ANSYS Fluent", "FEA", "CFD Simulation", "GD&T", "DFM", "EV Thermal Architecture"],
        "certifications": ["Certified SolidWorks Professional (CSWP)", "VDI Professional Engineer"],
        "projects": [
            {
                "title": "Modular Heat Exchanger for Fast Charging",
                "description": "Designed lightweight aluminum heat exchanger reducing peak cell temperature by 8 degrees Celsius.",
                "technologies": ["ANSYS", "CAD", "Thermal Optimization"],
            }
        ],
    },
    "creative_director": {
        "full_name": "Elena Rostova",
        "email": "elena@rostovastudio.com",
        "phone": "+1 (415) 555-7819",
        "location": "San Francisco, CA, USA",
        "headline": "Creative Director & Principal UX/UI Designer",
        "summary": "Visionary creative leader directing multidisciplinary brand identity, design systems, and consumer mobile application experiences for global lifestyle brands.",
        "education": [
            {
                "institution": "Rhode Island School of Design",
                "degree": "Bachelor of Fine Arts (B.F.A.)",
                "major": "Graphic Design",
                "expected_graduation_year": 2015,
                "cgpa": 3.9,
            }
        ],
        "work_experience": [
            {
                "employer": "Kinetic Creative Agency",
                "job_title": "Executive Creative Director",
                "duration": "60 months",
                "responsibilities": [
                    "Supervised creative team of 18 UI/UX designers, copywriters, and motion animators.",
                    "Established unified design systems for Fortune 500 digital products.",
                ],
            }
        ],
        "skills": ["Design Systems", "Figma", "Adobe Creative Suite", "UX Research", "Typography", "Art Direction", "Motion Graphics", "Wireframing"],
        "certifications": ["Nielsen Norman Group UX Master Certified"],
        "projects": [
            {
                "title": "Aura Smart Living Design System",
                "description": "Created comprehensive multi-platform design token system adopted across iOS, Android, and web.",
                "technologies": ["Figma", "Design Tokens", "Design Systems"],
            }
        ],
    },
    "cpa_auditor": {
        "full_name": "Robert Chen",
        "email": "robert.chen@auditcorp.com",
        "phone": "+1 (312) 555-6671",
        "location": "Chicago, IL, USA",
        "headline": "Senior Audit Manager | US GAAP & Sarbanes-Oxley (SOX) Specialist",
        "summary": "Certified Public Accountant with 9 years of public accounting experience conducting PCAOB audits and internal control reviews for public manufacturing entities.",
        "education": [
            {
                "institution": "University of Illinois Urbana-Champaign",
                "degree": "Bachelor of Science in Accounting",
                "major": "Accountancy",
                "expected_graduation_year": 2015,
                "cgpa": 3.78,
            }
        ],
        "work_experience": [
            {
                "employer": "Grant & Miller LLP",
                "job_title": "Senior Audit Manager",
                "duration": "84 months",
                "responsibilities": [
                    "Managed financial statement audit engagements for publicly traded manufacturing firms.",
                    "Tested internal controls under SOX Section 404 requirements.",
                ],
            }
        ],
        "skills": ["US GAAP", "SOX 404 Compliance", "PCAOB Auditing", "Revenue Recognition (ASC 606)", "Risk Assessment", "Workiva", "Tableau"],
        "certifications": ["Certified Public Accountant (CPA) – Illinois", "Certified Internal Auditor (CIA)"],
        "projects": [
            {
                "title": "Automated Audit Sampling Engine",
                "description": "Integrated statistical sampling script reducing audit workpaper preparation time by 30%.",
                "technologies": ["Excel", "ACL Analytics", "Python"],
            }
        ],
    },
    "stem_educator": {
        "full_name": "Dr. Marcus Holloway",
        "email": "m.holloway@austinstem.edu",
        "phone": "+1 (512) 555-8390",
        "location": "Austin, TX, USA",
        "headline": "AP Physics Educator & STEM Department Chair",
        "summary": "Passionate STEM educator and physicist with 12 years of secondary and collegiate classroom instruction, curriculum design, and robotics team mentoring.",
        "education": [
            {
                "institution": "University of Texas at Austin",
                "degree": "Doctor of Philosophy (Ph.D.)",
                "major": "Physics Education",
                "expected_graduation_year": 2013,
                "cgpa": 3.96,
            }
        ],
        "work_experience": [
            {
                "employer": "Westlake STEM Academy",
                "job_title": "Physics Department Chair",
                "duration": "96 months",
                "responsibilities": [
                    "Instructed AP Physics C (Mechanics and E&M) with a 94% pass rate.",
                    "Developed district-wide inquiry-based physics laboratory curriculum.",
                ],
            }
        ],
        "skills": ["Curriculum Design", "AP Physics", "Instructional Technology", "Classroom Management", "Laboratory Safety", "Student Mentorship", "Python"],
        "certifications": ["Texas Standard Educator Certificate (Physics 8-12)", "National Board Certified Teacher"],
        "projects": [
            {
                "title": "Interactive Computational Mechanics Lab",
                "description": "Authored open-source physics simulation modules in Python for high school calculus students.",
                "technologies": ["VPython", "Jupyter", "Physics Pedagogy"],
            }
        ],
    },
    "enterprise_sales": {
        "full_name": "Jessica Taylor",
        "email": "jtaylor@saasgrowth.com",
        "phone": "+1 (404) 555-1944",
        "location": "Atlanta, GA, USA",
        "headline": "Enterprise Account Executive | SaaS Annual Recurring Revenue Growth",
        "summary": "High-performing enterprise SaaS sales executive consistently exceeding multi-million dollar annual quotas across Fortune 500 healthcare and fintech accounts.",
        "education": [
            {
                "institution": "University of Georgia",
                "degree": "Bachelor of Arts in Marketing",
                "major": "Sales Leadership",
                "expected_graduation_year": 2016,
                "cgpa": 3.65,
            }
        ],
        "work_experience": [
            {
                "employer": "CloudScale Software",
                "job_title": "Enterprise Account Executive",
                "duration": "48 months",
                "responsibilities": [
                    "Closed $14.2M in Net New ARR over 3-year tenure at 145% quota achievement.",
                    "Negotiated multi-year master service agreements with C-level stakeholders.",
                ],
            }
        ],
        "skills": ["Enterprise B2B Sales", "MEDDIC Sales Methodology", "Pipeline Generation", "Contract Negotiation", "Salesforce CRM", "Executive Presentations"],
        "certifications": ["MEDDPICC Master Certified", "Salesforce Certified Administrator"],
        "projects": [
            {
                "title": "Strategic Healthcare Consortium Contract",
                "description": "Orchestrated $4.5M 3-year enterprise software contract spanning 12 regional hospital networks.",
                "technologies": ["Salesforce", "Gong.io", "Clari"],
            }
        ],
    },
    "special_education": {
        "full_name": "Hannah Abbott",
        "email": "hannah.abbott@denverschools.org",
        "phone": "+1 (303) 555-7281",
        "location": "Denver, CO, USA",
        "headline": "Board Certified Behavior Analyst (BCBA) & Special Educator",
        "summary": "Dedicated special education specialist and BCBA designing Individualized Education Programs (IEPs), functional behavior assessments, and classroom interventions.",
        "education": [
            {
                "institution": "University of Northern Colorado",
                "degree": "Master of Arts in Special Education",
                "major": "Applied Behavior Analysis",
                "expected_graduation_year": 2018,
                "cgpa": 3.91,
            }
        ],
        "work_experience": [
            {
                "employer": "Mile High Inclusive Learning Center",
                "job_title": "Lead Behavior Interventionist",
                "duration": "60 months",
                "responsibilities": [
                    "Authored and supervised 45+ comprehensive Individualized Education Programs.",
                    "Trained paraprofessionals in positive behavioral intervention strategies (PBIS).",
                ],
            }
        ],
        "skills": ["Applied Behavior Analysis", "IEP Development", "Functional Behavior Assessment", "Autism Spectrum Interventions", "PBIS", "Sensory Integration"],
        "certifications": ["Board Certified Behavior Analyst (BCBA)", "Colorado Special Education Generalist License"],
        "projects": [
            {
                "title": "Early Childhood Communication Board Program",
                "description": "Implemented augmentative and alternative communication (AAC) devices across 8 district preschool classrooms.",
                "technologies": ["AAC", "PECS", "Behavioral Data Tracking"],
            }
        ],
    },
    "supply_chain_director": {
        "full_name": "Carlos Mendez",
        "email": "carlos.mendez@globallogistics.com",
        "phone": "+1 (305) 555-3918",
        "location": "Miami, FL, USA",
        "headline": "Director of Global Supply Chain & Cold-Chain Logistics",
        "summary": "Global supply chain executive directing end-to-end multi-modal freight networks, customs compliance, and cold-chain pharmaceutical distribution across the Americas.",
        "education": [
            {
                "institution": "Florida International University",
                "degree": "Master of Science in Logistics and Supply Chain",
                "major": "International Freight Management",
                "expected_graduation_year": 2014,
                "cgpa": 3.82,
            }
        ],
        "work_experience": [
            {
                "employer": "Pan-American Logistics Partners",
                "job_title": "Senior Director of Operations",
                "duration": "84 months",
                "responsibilities": [
                    "Managed $85M annual freight procurement budget spanning ocean, air, and drayage.",
                    "Maintained 99.4% on-time delivery across refrigerated pharmaceutical lanes.",
                ],
            }
        ],
        "skills": ["Freight Forwarding", "SAP S/4HANA", "Customs Brokerage", "Cold-Chain Integrity", "Fleet Telematics", "Vendor Management", "Warehouse Automation"],
        "certifications": ["Certified Supply Chain Professional (CSCP)", "Lean Six Sigma Black Belt"],
        "projects": [
            {
                "title": "Port Congestion Diversion Strategy",
                "description": "Restructured shipping routes during major East Coast port strike, mitigating customer delay costs by $3.2M.",
                "technologies": ["SAP S/4HANA", "Tableau", "Telematics"],
            }
        ],
    },
    "biotech_scientist": {
        "full_name": "Dr. Emily Thorne",
        "email": "ethorne@cambiopharma.com",
        "phone": "+1 (617) 555-6129",
        "location": "Cambridge, MA, USA",
        "headline": "Principal Scientist | Oncology Biomarker Discovery",
        "summary": "Ph.D. molecular biologist leading translational immunology research, CRISPR-Cas9 target validation, and biomarker assay development for novel immunotherapies.",
        "education": [
            {
                "institution": "MIT Department of Biology",
                "degree": "Doctor of Philosophy (Ph.D.)",
                "major": "Molecular and Cellular Biology",
                "expected_graduation_year": 2017,
                "cgpa": 3.98,
            }
        ],
        "work_experience": [
            {
                "employer": "Beacon Oncology Therapeutics",
                "job_title": "Principal Biomarker Scientist",
                "duration": "72 months",
                "responsibilities": [
                    "Led cross-functional assay development team supporting Phase 1b clinical trials.",
                    "Supervised high-throughput flow cytometry and single-cell RNA sequencing studies.",
                ],
            }
        ],
        "skills": ["CRISPR-Cas9", "Flow Cytometry", "Next-Generation Sequencing", "Translational Oncology", "Bioinformatics", "R Programming", "FDA Regulatory Submissions"],
        "certifications": ["GLP / GCP Clinical Research Certified", "American Society of Clinical Oncology Member"],
        "projects": [
            {
                "title": "Target Identification for Immuno-Oncology Checkpoint",
                "description": "Discovered novel T-cell exhaustion biomarker resulting in 2 PCT international patent applications.",
                "technologies": ["single-cell RNA-seq", "R", "CRISPR"],
            }
        ],
    },
    "freshman_cs_student": {
        "full_name": "Kevin Patel",
        "email": "kevin.patel@punestudent.in",
        "phone": "+91 97654 32109",
        "location": "Pune, Maharashtra, India",
        "headline": "First-Year Computer Science Undergraduate | Aspiring Software Engineer",
        "summary": "Enthusiastic freshman student pursuing B.Tech in Computer Engineering with strong foundational coursework in Data Structures, Object-Oriented Programming, and web development.",
        "education": [
            {
                "institution": "Pune Institute of Computer Technology",
                "degree": "Bachelor of Technology (B.Tech)",
                "major": "Computer Engineering",
                "expected_graduation_year": 2028,
                "cgpa": 8.4,
            }
        ],
        "work_experience": [
            {
                "employer": "Campus Coding Society",
                "job_title": "Student Developer Coordinator",
                "duration": "6 months",
                "responsibilities": [
                    "Organized beginner programming workshops in C++ and Python for 120 peers.",
                    "Built registration web page for annual hackathon.",
                ],
            }
        ],
        "skills": ["Python", "C++", "HTML/CSS", "JavaScript", "Git", "Data Structures", "Algorithms"],
        "certifications": ["CS50 Introduction to Computer Science (Harvard Online)"],
        "projects": [
            {
                "title": "Smart Campus Lost and Found Web App",
                "description": "Developed full-stack web application for university students to report and search lost belongings.",
                "technologies": ["Python", "Flask", "SQLite", "HTML/CSS"],
            }
        ],
    },
    "hotel_gm": {
        "full_name": "Jean-Luc Moreau",
        "email": "jl.moreau@alohaluxuryresort.com",
        "phone": "+1 (808) 555-4019",
        "location": "Honolulu, HI, USA",
        "headline": "General Manager | 5-Star Luxury Resort & Hospitality Operations",
        "summary": "Accomplished hotel general manager with 15+ years delivering Forbes Five-Star hospitality standards, driving $60M P&L profitability, and cultivating high guest satisfaction.",
        "education": [
            {
                "institution": "Cornell University School of Hotel Administration",
                "degree": "Bachelor of Science in Hotel Administration",
                "major": "Hospitality Management",
                "expected_graduation_year": 2008,
                "cgpa": 3.75,
            }
        ],
        "work_experience": [
            {
                "employer": "Waikiki Grand Palms Luxury Resort",
                "job_title": "General Manager",
                "duration": "72 months",
                "responsibilities": [
                    "Oversaw daily operations of 420-room oceanfront resort with $65M annual revenue.",
                    "Achieved 96.2% guest satisfaction score and Forbes Five-Star recognition.",
                ],
            }
        ],
        "skills": ["Hotel P&L Management", "Forbes 5-Star Standards", "Food & Beverage Operations", "Revenue Management (RevPAR)", "Labor Relations", "Opera PMS"],
        "certifications": ["Certified Hotel Administrator (CHA)", "WSET Level 3 Wine Sommelier"],
        "projects": [
            {
                "title": "Comprehensive Property Renovation & Rebranding",
                "description": "Directed $22M guestroom refurbishment delivered on-schedule and under budget with zero guest disruption.",
                "technologies": ["Opera PMS", "HotSOS", "RevPAR Analytics"],
            }
        ],
    },
    "career_transitioner": {
        "full_name": "James Vance",
        "email": "james.vance@militarytransition.org",
        "phone": "+1 (619) 555-8832",
        "location": "San Diego, CA, USA",
        "headline": "Former Navy Surface Warfare Officer Transitioning to Data Analyst",
        "summary": "Former US Navy Lieutenant with 7 years of operational naval leadership and tactical communications management, now applying rigorous analytical discipline to SQL and business intelligence.",
        "education": [
            {
                "institution": "United States Naval Academy",
                "degree": "Bachelor of Science in Naval Architecture",
                "major": "Engineering Systems",
                "expected_graduation_year": 2017,
                "cgpa": 3.7,
            }
        ],
        "work_experience": [
            {
                "employer": "United States Navy",
                "job_title": "Combat Systems Officer / Lieutenant",
                "duration": "80 months",
                "responsibilities": [
                    "Supervised radar, satellite communication, and weapons maintenance for 65 sailors.",
                    "Analyzed readiness metrics and preventive maintenance compliance for guided-missile destroyer.",
                ],
            }
        ],
        "skills": ["SQL", "Tableau", "Power BI", "Python for Data Analysis", "Excel Modeling", "Operational Risk Management", "Crisis Leadership"],
        "certifications": ["Google Data Analytics Professional Certificate", "Defense Acquisition University Fundamentals"],
        "projects": [
            {
                "title": "Fleet Maintenance Predictive Readiness Dashboard",
                "description": "Constructed interactive Tableau dashboard modeling ship equipment failure rates using historical sensor logs.",
                "technologies": ["SQL", "Tableau", "Python"],
            }
        ],
    },
    "acca_finance_professional": {
        "full_name": "Pranjali Agrawal",
        "email": "pranjali.finance@synthetic-domain.org",
        "phone": "+91 98765 43210",
        "location": "Pune, India",
        "headline": "ACCA Member | Finance & Taxation Specialist",
        "summary": "ACCA Member with multi-year accounting and tax experience in UK tax compliance, SA100 Self Assessment filing, audit, and financial reporting.",
        "education": [
            {
                "institution": "MIT World Peace University",
                "degree": "BBA Finance",
                "major": "Finance",
                "expected_graduation_year": 2024,
                "cgpa": 7.69,
            },
            {
                "institution": "CBSE",
                "degree": "HSC Commerce",
                "major": "Commerce",
                "expected_graduation_year": 2021,
                "percentage": 93.8,
            },
        ],
        "work_experience": [
            {
                "employer": "Terra Global Partners",
                "job_title": "Tax Associate",
                "start_date": "2024-09",
                "end_date": "Present",
                "duration": "Present",
                "responsibilities": [
                    "Prepared SA100 Self Assessment tax returns and UK tax computations.",
                    "Handled HMRC correspondence and Making Tax Digital compliance.",
                ],
            },
            {
                "employer": "Apex Retail Audits",
                "job_title": "Stock Auditor",
                "start_date": "2024-01",
                "end_date": "2024-07",
                "duration": "7 months",
                "responsibilities": [
                    "Conducted comprehensive inventory audits and stock reconciliations.",
                    "Identified shrinkage discrepancies and improved internal stock controls.",
                ],
            },
            {
                "employer": "Global Accounting Solutions",
                "job_title": "Accounts Associate",
                "start_date": "2023-02",
                "end_date": "2024-01",
                "duration": "12 months",
                "responsibilities": [
                    "Managed accounts payable and supplier payment runs in Xero and ApprovalMax.",
                    "Conducted monthly balance sheet reconciliations and working capital analysis.",
                ],
            },
            {
                "employer": "Zenith Financial Corp",
                "job_title": "Internal Auditor",
                "start_date": "2022-08",
                "end_date": "2023-01",
                "duration": "6 months",
                "responsibilities": [
                    "Evaluated internal accounting controls and regulatory compliance.",
                    "Prepared audit reports and recommendations for senior management.",
                ],
            },
            {
                "employer": "Om Logistics & Trade",
                "job_title": "Accounts Executive",
                "start_date": "2021-01",
                "end_date": "2022-07",
                "duration": "19 months",
                "responsibilities": [
                    "Handled accounts receivable, invoicing, and debtor ledger reconciliation.",
                    "Prepared daily cash flow statements and vendor payment schedules.",
                ],
            },
        ],
        "per_experience": [
            {
                "employer": "Terra Global Partners",
                "job_title": "Supervised Tax & Accounting Trainee",
                "supervisory_context": "Supervised by Senior Tax Accountant / ACCA Member",
                "duration": "36 months",
                "responsibilities": [
                    "Completed ACCA Performance Objectives in UK Tax, Audit, and Financial Reporting.",
                    "Verified practical experience records signed off by registered practical experience supervisor.",
                ],
            }
        ],
        "skills": [
            "UK taxation",
            "SA100 Self Assessment",
            "Making Tax Digital",
            "Tax computations",
            "Tax compliance",
            "Accounts payable",
            "Supplier payment analysis",
            "Working capital analysis",
            "Financial reporting",
            "Internal audit",
            "Stock audit",
            "Receivables audit",
            "Internal controls",
            "Reconciliation",
        ],
        "tools_and_software": [
            "Digita",
            "FYI",
            "Xero",
            "ApprovalMax",
            "Coreplan",
            "Microsoft Office Suite",
        ],
        "languages": ["English", "Hindi", "Gujarati"],
        "certifications": ["ACCA Member"],
        "professional_qualifications": [
            {
                "name": "ACCA Member",
                "issuer": "Association of Chartered Certified Accountants",
                "membership": "Member",
            }
        ],
    },
    "cs_mobile_ai_student": {
        "full_name": "Rohan Sharma",
        "email": "rohan.sharma@synthetic-domain.org",
        "phone": "+91 91234 56789",
        "location": "Pune, India",
        "headline": "B.Tech Computer Science (AI & Data Science) Student",
        "summary": "Engineering student specializing in AI & Data Science with hands-on project experience in Flutter, Dart, Python, and full-stack API integration.",
        "education": [
            {
                "institution": "MIT World Peace University",
                "degree": "B.Tech Computer Science (AI & Data Science)",
                "major": "Computer Science",
                "expected_graduation_year": 2028,
                "cgpa": 7.6,
            }
        ],
        "work_experience": [
            {
                "employer": "Sarita Infotech Pvt. Ltd.",
                "job_title": "Project Manager | Mobile App Development",
                "start_date": "2024-05",
                "end_date": "2024-08",
                "duration": "3 months",
                "responsibilities": [
                    "Coordinated cross-functional mobile development team for healthcare application.",
                    "Integrated ABDM (Ayushman Bharat Digital Mission) compliant APIs into Flutter mobile app.",
                ],
            }
        ],
        "skills": ["Flutter", "Dart", "Python", "JavaScript", "C/C++", "SQLite", "MySQL", "REST API", "Git"],
        "projects": [
            {
                "title": "Medical Chatbot",
                "description": "AI-powered medical triage chatbot assisting patient symptom analysis using Python and NLP.",
                "technologies": ["Python", "FastAPI", "NLP", "SQLite"],
            },
            {
                "title": "Sarita ABDM Integration",
                "description": "Mobile healthcare module for QR patient registration and digital health records.",
                "technologies": ["Flutter", "Dart", "REST API"],
            },
        ],
    },
}


def generate_persona_docx(persona_id: str) -> bytes:
    """Generates a genuine DOCX document for the requested persona."""
    p = PERSONA_DEFINITIONS[persona_id]
    doc = Document()

    # Header / Contact
    doc.add_heading(p["full_name"], level=0)
    contact_parts = [p["email"], p["phone"], p["location"]]
    doc.add_paragraph(" | ".join(contact_parts))

    # Summary
    doc.add_heading("Professional Summary", level=1)
    doc.add_paragraph(p["summary"])

    # Education
    doc.add_heading("Education", level=1)
    for edu in p["education"]:
        score_str = f"CGPA: {edu['cgpa']}" if edu.get("cgpa") else (f"{edu['percentage']}%" if edu.get("percentage") else "")
        grad_yr = edu.get("expected_graduation_year") or edu.get("graduation_year", "")
        doc.add_paragraph(
            f"{edu.get('degree', '')} in {edu.get('major', '')}\n"
            f"{edu.get('institution', '')} | Class of {grad_yr} | {score_str}".strip(" |")
        )

    # Experience
    doc.add_heading("Work Experience", level=1)
    for exp in p["work_experience"]:
        doc.add_paragraph(f"{exp['job_title']} | {exp['employer']} | {exp['duration']}")
        for resp in exp["responsibilities"]:
            doc.add_paragraph(f"• {resp}")

    # Skills
    doc.add_heading("Skills & Competencies", level=1)
    doc.add_paragraph(", ".join(p["skills"]))

    # Certifications
    if p.get("certifications"):
        doc.add_heading("Certifications", level=1)
        for cert in p["certifications"]:
            doc.add_paragraph(f"• {cert}")

    # Projects
    if p.get("projects"):
        doc.add_heading("Projects", level=1)
        for proj in p["projects"]:
            doc.add_paragraph(f"{proj['title']}\n{proj['description']}\nTools: {', '.join(proj['technologies'])}")

    stream = io.BytesIO()
    doc.save(stream)
    return stream.getvalue()


def generate_persona_pdf(persona_id: str) -> bytes:
    """Generates a genuine PDF document for the requested persona."""
    p = PERSONA_DEFINITIONS[persona_id]
    stream = io.BytesIO()
    c = canvas.Canvas(stream, pagesize=letter)
    width, height = letter

    y = height - 50
    # Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, p["full_name"])
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"{p['email']}  |  {p['phone']}  |  {p['location']}")
    y -= 25

    # Summary
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Professional Summary")
    y -= 15
    c.setFont("Helvetica", 9)
    # wrap summary
    words = p["summary"].split()
    line = ""
    for w in words:
        if len(line + " " + w) > 95:
            c.drawString(50, y, line)
            y -= 12
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        c.drawString(50, y, line)
        y -= 20

    # Education
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Education")
    y -= 15
    for edu in p["education"]:
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, f"{edu['institution']}")
        y -= 12
        c.setFont("Helvetica", 9)
        c.drawString(50, y, f"{edu['degree']} in {edu['major']} | Graduation: {edu['expected_graduation_year']} | CGPA: {edu['cgpa']}")
        y -= 20

    # Experience
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Work Experience")
    y -= 15
    for exp in p["work_experience"]:
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, f"{exp['employer']} | {exp['job_title']} | {exp['duration']}")
        y -= 14
        c.setFont("Helvetica", 9)
        for r in exp["responsibilities"]:
            c.drawString(60, y, f"- {r[:90]}")
            y -= 12
        y -= 10

    # Skills
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Skills")
    y -= 15
    c.setFont("Helvetica", 9)
    c.drawString(50, y, ", ".join(p["skills"][:10]))
    y -= 20

    # Projects
    if p.get("projects"):
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Projects")
        y -= 15
        for proj in p["projects"]:
            c.setFont("Helvetica-Bold", 10)
            c.drawString(50, y, proj["title"])
            y -= 12
            c.setFont("Helvetica", 9)
            c.drawString(50, y, proj["description"][:95])
            y -= 15

    c.save()
    return stream.getvalue()


def generate_two_column_acca_pdf(persona_id: str = "acca_finance_professional") -> bytes:
    """Generates an authentic two-column, layout-aware PDF.

    Layout structure:
    - Top full-width header (x=50, y=740..770): Name, headline, contact info.
    - Left column (x=50..220): Education, Professional Qualifications, Domain Skills, Software, Languages.
    - Right column (x=240..560): Work Experience (5 distinct roles) and ACCA PER.
    """
    p = PERSONA_DEFINITIONS[persona_id]
    stream = io.BytesIO()
    c = canvas.Canvas(stream, pagesize=letter)
    width, height = letter

    # Page 1
    # Full-width Header
    y_hdr = height - 40
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y_hdr, p["full_name"])
    y_hdr -= 18
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y_hdr, p["headline"])
    y_hdr -= 14
    c.setFont("Helvetica", 8.5)
    c.drawString(50, y_hdr, f"{p['email']}  |  {p['phone']}  |  {p['location']}")
    y_hdr -= 10
    c.setLineWidth(0.5)
    c.line(50, y_hdr, width - 50, y_hdr)

    # Left Column (x=50)
    y_left = y_hdr - 20
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y_left, "Education")
    y_left -= 14
    for edu in p["education"]:
        c.setFont("Helvetica-Bold", 9)
        c.drawString(50, y_left, edu["institution"])
        y_left -= 11
        c.setFont("Helvetica", 8)
        score_str = f"CGPA: {edu.get('cgpa')}" if edu.get("cgpa") else f"{edu.get('percentage')}%"
        c.drawString(50, y_left, f"{edu['degree']} | {score_str} | {edu['expected_graduation_year']}")
        y_left -= 15

    # Professional Qualifications
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y_left, "Professional Qualifications")
    y_left -= 14
    for qual in p.get("professional_qualifications", []):
        c.setFont("Helvetica-Bold", 9)
        c.drawString(50, y_left, qual["name"])
        y_left -= 11
        c.setFont("Helvetica", 8)
        c.drawString(50, y_left, qual["issuer"])
        y_left -= 15

    # Domain Skills
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y_left, "Skills & Competencies")
    y_left -= 14
    c.setFont("Helvetica", 8)
    for sk in p["skills"][:8]:
        c.drawString(50, y_left, f"• {sk}")
        y_left -= 11
    y_left -= 4

    # Software & Tools
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y_left, "Software & Tools")
    y_left -= 14
    c.setFont("Helvetica", 8)
    for sw in p.get("tools_and_software", []):
        c.drawString(50, y_left, f"• {sw}")
        y_left -= 11
    y_left -= 4

    # Languages
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y_left, "Languages")
    y_left -= 14
    c.setFont("Helvetica", 8)
    c.drawString(50, y_left, ", ".join(p.get("languages", [])))

    # Right Column (x=240)
    y_right = y_hdr - 20
    c.setFont("Helvetica-Bold", 11)
    c.drawString(240, y_right, "Work Experience")
    y_right -= 14

    for exp in p["work_experience"][:3]:
        c.setFont("Helvetica-Bold", 9)
        c.drawString(240, y_right, f"{exp['job_title']} | {exp['employer']}")
        y_right -= 11
        c.setFont("Helvetica-Oblique", 8)
        c.drawString(240, y_right, f"{exp.get('start_date', '')} - {exp.get('end_date', '')} ({exp.get('duration', '')})")
        y_right -= 11
        c.setFont("Helvetica", 8)
        for resp in exp["responsibilities"]:
            c.drawString(245, y_right, f"- {resp[:65]}")
            y_right -= 10
        y_right -= 6

    # Page 2: Continuation of Experience & ACCA PER
    c.showPage()
    y_p2 = height - 40
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y_p2, f"{p['full_name']} — Experience & Credentials (Cont.)")
    y_p2 -= 12
    c.setLineWidth(0.5)
    c.line(50, y_p2, width - 50, y_p2)
    y_p2 -= 20

    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y_p2, "Work Experience (Cont.)")
    y_p2 -= 15

    for exp in p["work_experience"][3:]:
        c.setFont("Helvetica-Bold", 9.5)
        c.drawString(50, y_p2, f"{exp['job_title']} | {exp['employer']}")
        y_p2 -= 12
        c.setFont("Helvetica-Oblique", 8.5)
        c.drawString(50, y_p2, f"{exp.get('start_date', '')} - {exp.get('end_date', '')} ({exp.get('duration', '')})")
        y_p2 -= 12
        c.setFont("Helvetica", 8.5)
        for resp in exp["responsibilities"]:
            c.drawString(55, y_p2, f"- {resp[:85]}")
            y_p2 -= 11
        y_p2 -= 8

    # ACCA PER Section
    if p.get("per_experience"):
        y_p2 -= 10
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y_p2, "ACCA Practical Experience Requirement (PER)")
        y_p2 -= 15
        for per in p["per_experience"]:
            c.setFont("Helvetica-Bold", 9.5)
            c.drawString(50, y_p2, f"{per['job_title']} | {per.get('supervisory_context', '')}")
            y_p2 -= 12
            c.setFont("Helvetica", 8.5)
            c.drawString(50, y_p2, f"Duration: {per.get('duration', '')} | {per['employer']}")
            y_p2 -= 12
            for resp in per["responsibilities"]:
                c.drawString(55, y_p2, f"- {resp[:85]}")
                y_p2 -= 11
            y_p2 -= 8

    c.save()
    return stream.getvalue()

