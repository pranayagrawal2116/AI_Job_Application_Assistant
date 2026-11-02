# User Storage Directory

This directory stores private, user-isolated candidate documents:
```
data/users/<user_id>/
├── resumes/
│   └── <uuid4>.pdf
├── exports/
│   ├── tailored_resume_<uuid4>.pdf
│   └── tailored_resume_<uuid4>.docx
└── cover_letters/
    └── cover_letter_<uuid4>.md
```

All contents in subdirectories are strictly local and ignored by version control.
