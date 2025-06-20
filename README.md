# Cibersecurity Project with GO
It is based on a terminal interface in which a physician, once logged in, can add patients, observations and treatments to each patient. In addition, the same physician can add observations and treatments to patients of the same specialty.
The importance of this work lies in the decisions made to ensure safety rather than in functionality. 
Some of the main security measures are the use of ToTP for login, the generation of secure passwords, the use of hashing (with Argon2) to store passwords, the encryption of channels between clients and server with TLS, and the encryption of the data in the database itself.

Despite its simplicity, it has served to lay the groundwork for cybersecurity in clinical environments and to learn first-hand about the most commonly used algorithms in this context.

Feel free to use it by running the main.go applet and try all the features that this mini project offers. 

If more information is needed on how to use it or some other issues, feel free to contact me.
