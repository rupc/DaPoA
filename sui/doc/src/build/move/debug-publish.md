---
title: Debug and Publish the Sui Move Package
---

## Debugging a package
At the moment there isn't yet a debugger for Move. To help with debugging, however, you could use `std::debug` module to print out arbitrary value. To do so, first import the `debug` module:
```
use std::debug;
```
Then in places where you want to print out a value `v`, regardless of its type, simply do:
```
debug::print(&v);
```
or the following if v is already a reference:
```
debug::print(v);
```
The `debug` module also provides a function to print out the current stacktrace:
```
debug::print_stack_trace();
```
Alternatively, any call to `abort` or assertion failure will also print the stacktrace at the point of failure.

> **Important:** All calls to functions in the `debug` module must be removed from no-test code
> before the new module can be published (test code is marked with the `#[test]` annotation).

## Publishing a package

For functions in a Move package to actually be callable from Sui
(rather than for Sui execution scenario to be emulated), the package
has to be _published_ to Sui's [distributed ledger](../../learn/how-sui-works.md)
where it is represented as a Sui object.

At this point, however, the
`sui move` command does not support package publishing. In fact, it is
not clear if it even makes sense to accommodate package publishing,
which happens once per package creation, in the context of a unit
testing framework. Instead, one can use a Sui CLI client to
[publish](../cli-client.md#publish-packages) Move code and to
[call](../cli-client.md#calling-move-code) it. See the
[Sui CLI client documentation](../cli-client.md) for a description of how
to publish the package we have [written](write-package.md) as as
part of this tutorial.

### Module initializers

There is, however, an important aspect of publishing packages that
affects Move code development in Sui - each module in a package can
include a special _initializer function_ that will be run at the
publication time. The goal of an initializer function is to
pre-initialize module-specific data (e.g., to create singleton
objects). The initializer function must have the following properties
in order to be executed at publication:

- name `init`
- single parameter of `&mut TxContext` type
- no return values
- private visibility

While the `sui move` command does not support publishing explicitly,
we can still test module initializers using our testing framework -
one can simply dedicate the first transaction to executing the
initializer function. Let us use a concrete example to illustrate
this.

Continuing our fantasy game example, notice that we have used the init function in our tests, but have not tested it itself (in particular, the fact that it properly creates a Forge object):

``` rust
    // module initializer to be executed when this module is published
    fun init(ctx: &mut TxContext) {
        let admin = Forge {
            id: object::new(ctx),
            swords_created: 0,
        };
        // transfer the forge object to the module/package publisher
        // (presumably the game admin)
        transfer::transfer(admin, tx_context::sender(ctx));
    }
```

In order to do so, we need to modify the `sword_create`
function to take the forge as a parameter and to update the number of
created swords at the end of the function:

``` rust
    public entry fun sword_create(forge: &mut Forge, magic: u64, strength: u64, recipient: address, ctx: &mut TxContext) {
        ...
        forge.swords_created = forge.swords_created + 1;
    }
```

We can now create a function to test the module initialization:

``` rust
    #[test]
    public fun test_module_init() {
        use sui::test_scenario;

        // create test address representing game admin
        let admin = @0xBABE;

        // first transaction to emulate module initialization
        let scenario_val = test_scenario::begin(admin);
        let scenario = &mut scenario_val;
        {
            init(test_scenario::ctx(scenario));
        };
        // second transaction to check if the forge has been created
        // and has initial value of zero swords created
        test_scenario::next_tx(scenario, admin);
        {
            // extract the Forge object
            let forge = test_scenario::take_from_sender<Forge>(scenario);
            // verify number of created swords
            assert!(swords_created(&forge) == 0, 1);
            // return the Forge object to the object pool
            test_scenario::return_to_sender(scenario, forge);
        };
        test_scenario::end(scenario_val);
    }

```

As we can see in the test function defined above, in the first
transaction we (explicitly) call the initializer, and in the next
transaction we check if the forge object has been created and properly
initialized.

If we try to run tests on the whole package at this point, we will
encounter compilation errors in the existing tests due to the
`sword_create` function signature change. We will leave the changes
required for the tests to run again as an exercise for the reader. The
entire source code for the package we have developed (with all the
tests properly adjusted) can be found in
[my_module.move](https://github.com/MystenLabs/sui/tree/main/sui_programmability/examples/move_tutorial/sources/my_module.move).
