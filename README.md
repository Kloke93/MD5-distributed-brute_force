Instruction:

Turn on server, give it a MD5 hash and then 
connect clients by giving as an argument
in the terminal the server ip.

Protocol description:
- Delimiting messages with * in the end.

- Server:
  1) AIM: server sends what's the hash goal. AIM \<encoded md5 string>*
  2) BLK: server sends a block to work with. BLK <initial_value> to <end_value>*
  3) GOT: server notifies that it found the answer. GOT*

- Client:
  1) ASK: client asks for an amount of blocks. ASK <#blocks>*
  2) SOL: client sends solution to the server. SOL \<original string>*
