---
title: Chapter 6 - Collections
---

The last chapter introduces a way to extend existing objects with *dynamic fields*, but noted that it's possible to delete an object that still has (potentially non-`drop`) dynamic fields. This may not be a concern when adding a small number of statically known additional fields to an object, but is particularly undesirable for *on-chain collection types* which could be holding unboundedly many key-value pairs as dynamic fields.

This chapter covers two such collections -- `Table` and `Bag` -- built using dynamic fields, but with additional support to count the number of entries they contain, and protect against accidental deletion when non-empty.

The types and function discussed below are built into the Sui framework in modules [`table`](https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/sources/table.move) and [`bag`](https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/sources/bag.move). As with dynamic fields, there is also an `object_` variant of both: `ObjectTable` in [`object_table`](https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/sources/object_table.move) and `ObjectBag` in [`object_bag`](https://github.com/MystenLabs/sui/blob/main/crates/sui-framework/sources/object_bag.move). The relationship between `Table` and `ObjectTable`, and `Bag` and `ObjectBag` are the same as between a field and an object field: The former can hold any `store` type as a value, but objects stored as values will be hidden when viewed from external storage. The latter can only store objects as values, but keeps those objects visible at their ID in external storage.

### Current Limitations

Collections are built on top of [dynamic fields](ch5-dynamic-fields.md), and so are subject to its [limitations](ch5-dynamic-fields.md#current-limitations). Additionally, the following functionality is planned, but not currently supported:

- `sui::bag::contains<K: copy + drop + store>(bag: &Bag, k: K): bool` which checks whether a key-value pair exists in `bag` with key `k: K` and a value of any type (in addition to `contain_with_type` which performs a similar check, but requires passing a specific value type).


### Tables

```rust
module sui::table {

struct Table<K: copy + drop + store, V: store> has key, store { /* ... */ }

public fun new<K: copy + drop + store, V: store>(
    ctx: &mut TxContext,
): Table<K, V>;

}
```

`Table<K, V>` is a *homogeneous* map, meaning that all its keys have the same type as each other (`K`), and all its values have the same type as each other as well (`V`). It is created with `sui::table::new`, which requires access to a `&mut TxContext` because `Table`s are objects themselves, which can be transferred, shared, wrapped, or unwrapped, just like any other object.

> :bulb: See `sui::bag::ObjectTable` for the object-preserving version of `Table`.

### Bags

```rust
module sui::bag {

struct Bag has key, store { /* ... */ }

public fun new(ctx: &mut TxContext): Bag;

}
```

`Bag` is a *heterogeneous* map, so it can hold key-value pairs of arbitrary types (they don't need to match each other). Note that the `Bag` type does not have any type parameters for this reason. Like `Table`, `Bag` is also an object, so creating one with `sui::bag::new` requires supplying a `&mut TxContext` to generate an ID.

> :bulb: See `sui::bag::ObjectBag` for the object-preserving version of `Bag`.

---

The following sections explain the collection APIs. `sui::table` will be used as the basis for code examples, with explanations where other modules differ.

### Interacting with Collections

All collection types come with the following functions, defined in their respective modules:

```rust
module sui::table {

public fun add<K: copy + drop + store, V: store>(
    table: &mut Table<K, V>,
    k: K,
    v: V,
);

public fun borrow<K: copy + drop + store, V: store>(
    table: &Table<K, V>,
    k: K
): &V;

public fun borrow_mut<K: copy + drop + store, V: store>(
    table: &mut Table<K, V>,
    k: K
): &mut V;

public fun remove<K: copy + drop + store, V: store>(
    table: &mut Table<K, V>,
    k: K,
): V;

}
```

These functions, add, read, write, and remove entries from the collection, respectively, and all accept keys by value. `Table` has type parameters for `K` and `V` so it is not possible to call these functions with different instantiations of `K` and `V` on the same instance of `Table`, however `Bag` does not these type parameters, and so does permit calls with different instantiations on the same instance.

> :warning: Like with dynamic fields, it is an error to attempt to overwrite an existing key, or access or remove a non-existent key.

> :warning: The extra flexibility of `Bag`'s heterogeneity means the type system will not statically prevent attempts to add a value with one type, and then borrow or remove it at another type. This pattern will fail at runtime with an abort, similar to the behavior for dynamic fields.

### Querying Length

It is possible to query all collection types for their length and check whether they are empty using the following family of functions:

```rust
module sui::table {

public fun length<K: copy + drop + store, V: store>(
    table: &Table<K, V>,
): u64;

public fun is_empty<K: copy + drop + store, V: store>(
    table: &Table<K, V>
): bool;

}
```

> :bulb: `Bag` has these APIs, but they are not generic on `K` and `V` because `Bag` does not have these type parameters.

### Querying for Containment

All collections can be queried for key containment with:

```rust
module sui::table {

public fun contains<K: copy + drop + store, V: store>(
    table: &Table<K, V>
    k: K
): bool;

}
```

The equivalent function for `Bag` is,

```rust
module sui::bag {

public fun contains_with_type<K: copy + drop + store, V: store>(
    bag: &Bag,
    k: K
): bool;

}
```

which tests whether `bag` contains a key-value pair with key `k: K` and some value of type `V`.

### Clean-up

As mentioned in the introduction, collection types protect against accidental deletion when they might not be empty. This protection comes from the fact that they do not have `drop`, so must be explicitly deleted, using this API:

```rust
module sui::table {

public fun destroy_empty<K: copy + drop + store, V: store>(
    table: Table<K, V>,
);

}
```

This function takes the collection by value. If it contains no entries, it will be deleted, otherwise the call will abort. `sui::table::Table` also has a convenience function,

```rust
module sui::table {

public fun drop<K: copy + drop + store, V: drop + store>(
    table: Table<K, V>,
);

}
```

that can only be called for tables where the value type also has `drop`, which allows it to delete tables whether they are empty or not.

> :bulb: Note that `drop` will not be called implicitly on eligible tables, before they go out of scope.  It must be called explicitly, but it is guaranteed to succeed at runtime.

> :bulb: `Bag` and `ObjectBag` cannot support `drop` because they could be holding a variety of types, some of which may have `drop` and some which may not.

> :bulb: `ObjectTable` does not support `drop` because its values must be objects, which cannot be drop (because they must contain an `id: UID` field and `UID` does not have `drop`).

### :warning: Equality

Equality on collections is based on identity, i.e. an instance of a collection type is only considered equal to itself and not to all collections that hold the same entries:

```rust
let t1 = sui::table::new<u64, u64>(ctx);
let t2 = sui::table::new<u64, u64>(ctx);

assert!(&t1 == &t1, 0);
assert!(&t1 != &t2, 1);
```

This is unlikely to be the definition of equality that you want, don't use it!
