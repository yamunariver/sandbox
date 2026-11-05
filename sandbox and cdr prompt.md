CDR and Sandbox implementation in SFT web Application.
In the SFT application, Kaspersky Endpoint scans uploaded files, but we now need to implement CDR and Sandbox.

Sandboxing opens uploaded files and observes behaviour patterns; CDR reconstructs the uploaded files after rebuilding the file format, formulas, macros, and links, removing problematic content, and rebuilding the file using only secure content. But we should not lose the above-mentioned things.
Can you configure the CDR without losing the original, and have the rebuilt and original files displayed in the web application for download?

Decide whether the sandbox and CDR tool should be free, or write the tool from scratch.
Write a script to manage the sandbox and CDR tool. Not for a demo, but for a production-grade application.
Explain in simple English before writing code.



