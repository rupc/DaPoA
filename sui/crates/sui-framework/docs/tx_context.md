
<a name="0x2_tx_context"></a>

# Module `0x2::tx_context`



-  [Struct `TxContext`](#0x2_tx_context_TxContext)
-  [Constants](#@Constants_0)
-  [Function `sender`](#0x2_tx_context_sender)
-  [Function `epoch`](#0x2_tx_context_epoch)
-  [Function `epoch_timestamp`](#0x2_tx_context_epoch_timestamp)
-  [Function `new_object`](#0x2_tx_context_new_object)
-  [Function `ids_created`](#0x2_tx_context_ids_created)
-  [Function `derive_id`](#0x2_tx_context_derive_id)


<pre><code></code></pre>



<a name="0x2_tx_context_TxContext"></a>

## Struct `TxContext`

Information about the transaction currently being executed.
This cannot be constructed by a transaction--it is a privileged object created by
the VM and passed in to the entrypoint of the transaction as <code>&<b>mut</b> <a href="tx_context.md#0x2_tx_context_TxContext">TxContext</a></code>.


<pre><code><b>struct</b> <a href="tx_context.md#0x2_tx_context_TxContext">TxContext</a> <b>has</b> drop
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>sender: <b>address</b></code>
</dt>
<dd>
 The address of the user that signed the current transaction
</dd>
<dt>
<code>tx_hash: <a href="">vector</a>&lt;u8&gt;</code>
</dt>
<dd>
 Hash of the current transaction
</dd>
<dt>
<code>epoch: u64</code>
</dt>
<dd>
 The current epoch number
</dd>
<dt>
<code>epoch_timestamp_ms: u64</code>
</dt>
<dd>
 Timestamp that the epoch started at
</dd>
<dt>
<code>ids_created: u64</code>
</dt>
<dd>
 Counter recording the number of fresh id's created while executing
 this transaction. Always 0 at the start of a transaction
</dd>
</dl>


</details>

<a name="@Constants_0"></a>

## Constants


<a name="0x2_tx_context_EBadTxHashLength"></a>

Expected an tx hash of length 32, but found a different length


<pre><code><b>const</b> <a href="tx_context.md#0x2_tx_context_EBadTxHashLength">EBadTxHashLength</a>: u64 = 0;
</code></pre>



<a name="0x2_tx_context_TX_HASH_LENGTH"></a>

Number of bytes in an tx hash (which will be the transaction digest)


<pre><code><b>const</b> <a href="tx_context.md#0x2_tx_context_TX_HASH_LENGTH">TX_HASH_LENGTH</a>: u64 = 32;
</code></pre>



<a name="0x2_tx_context_sender"></a>

## Function `sender`

Return the address of the user that signed the current
transaction


<pre><code><b>public</b> <b>fun</b> <a href="tx_context.md#0x2_tx_context_sender">sender</a>(self: &<a href="tx_context.md#0x2_tx_context_TxContext">tx_context::TxContext</a>): <b>address</b>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="tx_context.md#0x2_tx_context_sender">sender</a>(self: &<a href="tx_context.md#0x2_tx_context_TxContext">TxContext</a>): <b>address</b> {
    self.sender
}
</code></pre>



</details>

<a name="0x2_tx_context_epoch"></a>

## Function `epoch`

Return the current epoch


<pre><code><b>public</b> <b>fun</b> <a href="tx_context.md#0x2_tx_context_epoch">epoch</a>(self: &<a href="tx_context.md#0x2_tx_context_TxContext">tx_context::TxContext</a>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="tx_context.md#0x2_tx_context_epoch">epoch</a>(self: &<a href="tx_context.md#0x2_tx_context_TxContext">TxContext</a>): u64 {
    self.epoch
}
</code></pre>



</details>

<a name="0x2_tx_context_epoch_timestamp"></a>

## Function `epoch_timestamp`

Return the epoch start time as a unix timestamp in milliseconds.


<pre><code><b>public</b> <b>fun</b> <a href="tx_context.md#0x2_tx_context_epoch_timestamp">epoch_timestamp</a>(self: &<a href="tx_context.md#0x2_tx_context_TxContext">tx_context::TxContext</a>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="tx_context.md#0x2_tx_context_epoch_timestamp">epoch_timestamp</a>(self: &<a href="tx_context.md#0x2_tx_context_TxContext">TxContext</a>): u64 {
   self.epoch_timestamp_ms
}
</code></pre>



</details>

<a name="0x2_tx_context_new_object"></a>

## Function `new_object`

Generate a new, globally unique object ID with version 0


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="tx_context.md#0x2_tx_context_new_object">new_object</a>(ctx: &<b>mut</b> <a href="tx_context.md#0x2_tx_context_TxContext">tx_context::TxContext</a>): <b>address</b>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="tx_context.md#0x2_tx_context_new_object">new_object</a>(ctx: &<b>mut</b> <a href="tx_context.md#0x2_tx_context_TxContext">TxContext</a>): <b>address</b> {
    <b>let</b> ids_created = ctx.ids_created;
    <b>let</b> id = <a href="tx_context.md#0x2_tx_context_derive_id">derive_id</a>(*&ctx.tx_hash, ids_created);
    ctx.ids_created = ids_created + 1;
    id
}
</code></pre>



</details>

<a name="0x2_tx_context_ids_created"></a>

## Function `ids_created`

Return the number of id's created by the current transaction.
Hidden for now, but may expose later


<pre><code><b>fun</b> <a href="tx_context.md#0x2_tx_context_ids_created">ids_created</a>(self: &<a href="tx_context.md#0x2_tx_context_TxContext">tx_context::TxContext</a>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="tx_context.md#0x2_tx_context_ids_created">ids_created</a>(self: &<a href="tx_context.md#0x2_tx_context_TxContext">TxContext</a>): u64 {
    self.ids_created
}
</code></pre>



</details>

<a name="0x2_tx_context_derive_id"></a>

## Function `derive_id`

Native function for deriving an ID via hash(tx_hash || ids_created)


<pre><code><b>fun</b> <a href="tx_context.md#0x2_tx_context_derive_id">derive_id</a>(tx_hash: <a href="">vector</a>&lt;u8&gt;, ids_created: u64): <b>address</b>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>native</b> <b>fun</b> <a href="tx_context.md#0x2_tx_context_derive_id">derive_id</a>(tx_hash: <a href="">vector</a>&lt;u8&gt;, ids_created: u64): <b>address</b>;
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>aborts_if</b> [abstract] <b>false</b>;
</code></pre>



</details>
