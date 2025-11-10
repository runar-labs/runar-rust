GOAL IMPLEMENT THE  /home/rafael/Development/runar-rust/runar-nodejs-api/NodeJS_API_DESIGN.md

STEP 1: CHECK THE CURRENT CODE AT /home/rafael/Development/runar-rust/runar-nodejs-api against the document and to determine what needs to be done next. CHECK IT PROPELY AND IN DETAILS DO NOT MAKE ASSUMPTIONS> THE CODE IS THR TRUTH. CHECK IT PROPERLY AND SYSTEMATICAOY AND METHODICALY LINE BY LINE TO MAKE SURE U IMPLEMENTE EVERYTHIG HTA IS MISSING AND DO NOT DUPLICATION THINGS

We user bun and NOT node/npm as our runtime. Always use bun for everything to manakge package and to run ts code.

STEP 2: IMplement feature by featyres and test it properly. Follow the /home/rafael/Development/runar-rust/runar-ffi for guidenance on every features and also on all the tests. THe nodejs API must match the FFI 100% and also the test must match 100%

STEP 3: Test the features, use the FFI tests as guidance runar-ffi/tests  the node js tests must also match 100% the FFI tests.. test must have exactly same setup, same steps, same asserts. 100% alignemnt.

SET 4: After each features, review the code to make sure:
A) Follow all he best practices in NodeJS APIS , in the Rust code and in the TS code.
B) compare the code in the nodejS API with the runar-rust/runar-ffi code. to double check and make sure it it 100% aligned, nothing is missing. nothing more nothing less. no exceptions.

IF You get stuck or have issues, stop and ask for guidance. DO NOT HACK THINGS.  DO NOT TRY TO SIMPLIFY ANYTHING. DO NOT MOCK, STUB. DO NOT ADD TODOs NO SHORTCUTS.
YOU MUST DO PROPER ROBUST CODE, following best practice. YOu must implement all features completely.

All tests must be using real components testing real functionality NO MOCKs, NO STUB. DO NOT ADD TODOs NO SHORTCUTS.

Follow our code standards /home/rafael/Development/runar-rust/.cursor/rules/codeformat.mdc

 REMOVE old patterns/code - 
 DO NOT DEPRECATE ANYTHING 
 DO NOT LEAVE OLD CODE BEHAIND  
 REMOVE all old not used stuff 
 NO BACKWARDS COMPATIBIILITY -> THIS IS A NEW CODEBASE. KEEP IT CLEAN AND ORGANIZED and aligned with the final design and the FFI crate nothing more, nothing less


 DO NOT CHANGE ANYTIHNG OURSIDE THE runar-nodejs-api crate. 