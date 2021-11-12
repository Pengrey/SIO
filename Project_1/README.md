# Project 1 - Vulnerabilities

### Description

This assignment will focus on the existence of vulnerabilities in software projects, their exploration and avoidance. The objective is for students to develop a small application, with a simple and clear purpose. An online shop, a forum, a wiki, or a RESTFull service are good examples of what is expected. The application should provide its function without errors, without inconsistent behaviour, and without pages/sections/fragments that do not fit the purpose of the application.

However, this application should also suffer from a specific set of weaknesses, which are not obvious to the casual user, but may be used to compromise the application, or the system.

Students should provide a both a flawed and correct version of the application, together with a report demonstrating how those vulnerabilities are explored and their impact. The project must include vulnerabilities associated with [CWE-79](https://cwe.mitre.org/data/definitions/79.html) and [CWE-89](https://cwe.mitre.org/data/definitions/89.html). An additional set of weaknesses must be considered, so that the total number of vulnerabilities should be of at least 4.

For all vulnerabilities:

- Vulnerabilities should be distinct (different CWEs);
- The CWE must be identified;
- The implementation must follow the logic and purpose of the application;
- Students should be able to demonstrate the vulnerability;

A bonus of 10% can be provided if the vulnerability is subtle (needs a careful analysis), can be attributed to a bug (developer can repudiate having authored the vulnerability).

It is expected that a user can fully understand the purpose of the application, and use it. Implementation can be simple and some functions may be missing (e.g. if it’s a book store, the back-end can be omitted). After reading the report, a reader should be able to understand the application, the vulnerabilities, their exploration and impact, and how they can be avoided.

The project is expected to be implemented by **a group of 4 students**, and **MUST** reside in a private repository in the [github/detiuaveiro](https://github.com/detiuaveiro) organization, using the Github Classroom functionality (this is mandatory).

### Project delivery

Delivery should consist of a git repository with at least three folders and a file:

- `app`: contains the insecure application, including instructions to run it.
- `app_sec`: contains the secure application, including instructions to run it.
- `analysis`: contains scripts/textual descriptions/logs/screen captures demonstrating the exploration of each vulnerability and the fix implemented;
- `README.md`: contains the project description, authors, identifies vulnerabilities implemented;

Projects will be graded according to the CWE (e.g, its score), the implementation and exploration of the flawed code, the implementation of the secure code, and the documentation produced.

The use of automated tools to scan the application is not forbidden. 
However, grading will mostly consider your work and your analysis, not on the findings (as they are deliberate).

This project is expected to be authored by the students enrolled in the course. The use of existing code snippets, applications, or any other external functional element without proper acknowledgement is strictly forbidden. Themes and python/php/javascript libraries can be used, as long as the vulnerabilities are created by the students. If any content lacking proper acknowledgment is found in other sources, the 
current rules regarding plagiarism will be followed.