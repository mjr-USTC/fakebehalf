# fakebehalf
### Introduction
This project provides several additional test cases for email spoofing attacks on the basis of espoofer, which is developed by Chenjj (https://github.com/chenjj/espoofer). Thanks for the wonderful work!

### Main changes
The primary changes include the two following ascepts:
- Add more practical test cases in testcases.py;
- Exploit the issues within the email delegation mechanism to conceal the attacker's identity;

In addition, there are several minor changes, including the log configure, and append a param '-to' for convenient evaluation. The file run.py provides a tool for automatic test on given targets.

### Explanation
This repo is primarily based on the open-sourced project espoofer (the Github link is https://github.com/chenjj/espoofer), please go star it for detailed manual. 
Although we have reported these issues to related providers, this repo is used only for study and security testing, do not use it for real attacks!
