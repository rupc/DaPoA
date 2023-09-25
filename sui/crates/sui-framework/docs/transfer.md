
<a name="0x2_transfer"></a>

# Module `0x2::transfer`



-  [Constants](#@Constants_0)
-  [Function `transfer`](#0x2_transfer_transfer)
-  [Function `freeze_object`](#0x2_transfer_freeze_object)
-  [Function `share_object`](#0x2_transfer_share_object)
-  [Function `transfer_internal`](#0x2_transfer_transfer_internal)


<pre><code></code></pre>



<a name="@Constants_0"></a>

## Constants


<a name="0x2_transfer_ESharedNonNewObject"></a>

Shared an object that was previously created. Shared objects must currently
be constructed in the transaction they are created.


<pre><code><b>const</b> <a href="transfer.md#0x2_transfer_ESharedNonNewObject">ESharedNonNewObject</a>: u64 = 0;
</code></pre>



<a name="0x2_transfer_transfer"></a>

## Function `transfer`

Transfer ownership of <code>obj</code> to <code>recipient</code>. <code>obj</code> must have the
<code>key</code> attribute, which (in turn) ensures that <code>obj</code> has a globally
unique ID.


<pre><code><b>public</b> <b>fun</b> <a href="transfer.md#0x2_transfer">transfer</a>&lt;T: key&gt;(obj: T, recipient: <b>address</b>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="transfer.md#0x2_transfer">transfer</a>&lt;T: key&gt;(obj: T, recipient: <b>address</b>) {
    // TODO: emit <a href="event.md#0x2_event">event</a>
    <a href="transfer.md#0x2_transfer_transfer_internal">transfer_internal</a>(obj, recipient)
}
</code></pre>



</details>

<a name="0x2_transfer_freeze_object"></a>

## Function `freeze_object`

Freeze <code>obj</code>. After freezing <code>obj</code> becomes immutable and can no
longer be transferred or mutated.


<pre><code><b>public</b> <b>fun</b> <a href="transfer.md#0x2_transfer_freeze_object">freeze_object</a>&lt;T: key&gt;(obj: T)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>native</b> <b>fun</b> <a href="transfer.md#0x2_transfer_freeze_object">freeze_object</a>&lt;T: key&gt;(obj: T);
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>aborts_if</b> [abstract] <b>false</b>;
<b>modifies</b> [abstract] <b>global</b>&lt;<a href="object.md#0x2_object_Ownership">object::Ownership</a>&gt;(<a href="object.md#0x2_object_id">object::id</a>(obj).bytes);
<b>ensures</b> [abstract] <b>exists</b>&lt;<a href="object.md#0x2_object_Ownership">object::Ownership</a>&gt;(<a href="object.md#0x2_object_id">object::id</a>(obj).bytes);
<b>ensures</b> [abstract] <b>global</b>&lt;<a href="object.md#0x2_object_Ownership">object::Ownership</a>&gt;(<a href="object.md#0x2_object_id">object::id</a>(obj).bytes).status == <a href="prover.md#0x2_prover_IMMUTABLE">prover::IMMUTABLE</a>;
</code></pre>



</details>

<a name="0x2_transfer_share_object"></a>

## Function `share_object`

Turn the given object into a mutable shared object that everyone
can access and mutate. This is irreversible, i.e. once an object
is shared, it will stay shared forever.
Aborts with <code><a href="transfer.md#0x2_transfer_ESharedNonNewObject">ESharedNonNewObject</a></code> of the object being shared was not created
in this transaction. This restriction may be relaxed in the future.


<pre><code><b>public</b> <b>fun</b> <a href="transfer.md#0x2_transfer_share_object">share_object</a>&lt;T: key&gt;(obj: T)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>native</b> <b>fun</b> <a href="transfer.md#0x2_transfer_share_object">share_object</a>&lt;T: key&gt;(obj: T);
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>aborts_if</b> [abstract] sui::prover::owned(obj);
<b>modifies</b> [abstract] <b>global</b>&lt;<a href="object.md#0x2_object_Ownership">object::Ownership</a>&gt;(<a href="object.md#0x2_object_id">object::id</a>(obj).bytes);
<b>ensures</b> [abstract] <b>exists</b>&lt;<a href="object.md#0x2_object_Ownership">object::Ownership</a>&gt;(<a href="object.md#0x2_object_id">object::id</a>(obj).bytes);
<b>ensures</b> [abstract] <b>global</b>&lt;<a href="object.md#0x2_object_Ownership">object::Ownership</a>&gt;(<a href="object.md#0x2_object_id">object::id</a>(obj).bytes).status == <a href="prover.md#0x2_prover_SHARED">prover::SHARED</a>;
</code></pre>



</details>

<a name="0x2_transfer_transfer_internal"></a>

## Function `transfer_internal`



<pre><code><b>fun</b> <a href="transfer.md#0x2_transfer_transfer_internal">transfer_internal</a>&lt;T: key&gt;(obj: T, recipient: <b>address</b>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>native</b> <b>fun</b> <a href="transfer.md#0x2_transfer_transfer_internal">transfer_internal</a>&lt;T: key&gt;(obj: T, recipient: <b>address</b>);
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>pragma</b> opaque;
<b>aborts_if</b> [abstract] <b>false</b>;
<b>modifies</b> [abstract] <b>global</b>&lt;<a href="object.md#0x2_object_Ownership">object::Ownership</a>&gt;(<a href="object.md#0x2_object_id">object::id</a>(obj).bytes);
<b>ensures</b> [abstract] <b>exists</b>&lt;<a href="object.md#0x2_object_Ownership">object::Ownership</a>&gt;(<a href="object.md#0x2_object_id">object::id</a>(obj).bytes);
<b>ensures</b> [abstract] <b>global</b>&lt;<a href="object.md#0x2_object_Ownership">object::Ownership</a>&gt;(<a href="object.md#0x2_object_id">object::id</a>(obj).bytes).owner == recipient;
<b>ensures</b> [abstract] <b>global</b>&lt;<a href="object.md#0x2_object_Ownership">object::Ownership</a>&gt;(<a href="object.md#0x2_object_id">object::id</a>(obj).bytes).status == <a href="prover.md#0x2_prover_OWNED">prover::OWNED</a>;
</code></pre>



</details>
