Notes taking app.

To demostrate runnar this notes taking app use end to end encyption to protect the users data, while allowing the content to be securely
stored in a backend, with key words and metadata searching without ever revealing the users private data




entities..
USer Profile

id
name (user and system and search)
email (user and system and search)
age (user )
sex (user )


Notes
id
content (user)
keywords (user, system, search)
created_date (user, ssytem, search)
modified_date (user, ssytem, search)



Pictures
id
content (user)
keywords (user, system, search)
created_date (user, ssytem, search)
modified_date (user, ssytem, search)




THis app has teo sides, mobile side and backend side. 

the backend services, that run in the nodes to backed up the user data, and the client side, that runs in the users mobile

BAckend as SQL lite storage, and a service that uses the use the seach field as plain text to store in sql liste .. so search can work.


The client side is were notes de taken and also the key words are populated from the notes content. or the user can also modify  them

. This is an exmaple codebase. and we dont have the swift side ready, so ., so both sides will be coded in rust.. to demostrate the framework
capabilioties and hownit works..


The data flows that tbhis example shuodl demostratte are:
1) app startes empty, on the user side few notes are created.. and stored localy in the mobile scope.  (Thios example needs the data replciation feagaure.. not yet implemented.)