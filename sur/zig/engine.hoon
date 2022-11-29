/+  smart=zig-sys-smart, zink=zink-zink
|%
++  big  (bi:smart id:smart item:smart)  ::  merkle engine for state
++  pig  (bi:smart id:smart @ud)         ::                for nonces
::
+$  state   (merk:smart id:smart item:smart)
+$  nonces  (merk:smart address:smart @ud)
+$  chain   (pair state nonces)
::
+$  mempool  (set [hash=@ux tx=transaction:smart])   ::  transaction mempool
+$  memlist  (list [hash=@ux tx=transaction:smart])  ::  sorted mempool
+$  processed-txs  (list [tx-hash=@ux tx=transaction:smart =output])
::
+$  state-diff  state  ::  state transitions for one batch
::
::  The engine, at the top level, takes in a chain-state and mempool
::  and produces the resulting state-transition, shown below
::
+$  state-transition
  $:  =chain
      modified=state
      burned=state
      processed=processed-txs
  ==
::
+$  output
  $:  gas=@ud
      =errorcode:smart
      modified=state
      burned=state
      events=(list contract-event)
  ==
::
::  contract events are converted to this
::
+$  contract-event  [contract=id:smart label=@tas =json]
--
