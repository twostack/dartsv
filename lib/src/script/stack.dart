import 'dart:collection';

/// Utility class to represent the Script Interpreter Stack.
///
/// This class is used internally by the Script Interpreter, and should not really be useful in everyday wallet development.
///
class InterpreterStack {
    Queue<List<int>> _queue = new Queue<List<int>>();

    InterpreterStack();

    /// Construct a stack instance from a Dart Queue
    ///
    /// Dart does not have a native representation for a Stack. This implementation
    /// wraps a Queue datastructure with the needed operations.
    /// Each element in the stack is represented as a byte buffer in the Queue.
    InterpreterStack.fromQueue(Queue<List<int>> queue){
        this._queue = Queue.from(queue);
    }

    /// push an element onto the stack
    void push(List<int> item) {
        _queue.addLast(List.from(item));
    }

    /// get the height of the stack
    int get length => _queue.length;

    /// remove all items from the stack
    void removeAll() {
        this._queue.clear();
    }

    /// convenience method to create a copy of the stack
    InterpreterStack slice() {
        return InterpreterStack.fromQueue(_queue);
    }

    /// Return the item at the specified index on the stack without modifying the stack
    ///
    /// `index` - a negative number specifying how deep into the stack we want to "peek"
    List<int> peek({int index = -1}) {
        if (index > 0) {
            throw new StackOverflowError();
        }

        if (index > _queue.length - 1) {
            throw new Exception("Can't peek past the first element");
        }
        var retval = _queue.elementAt(_queue.length + index); //FIXME: Validate this !
        retval.runtimeType;
        return retval;

    }

    /// Remove the item at the top of the stack and return it as a byte buffer
    List<int> pop() {
        return _queue.removeLast();
    }

    /// Removes items from the stack and optionally inserts new values
    ///
    /// `index` - starting index for items to be removed
    ///
    /// `howMany` - the number of items to be removed
    ///
    /// `values`  - an optional List of new items to add to the stack, or null if no items need insertion
    List<List<int>> splice(int index, int howMany, {List<int> values}) {
        List<List<int>> buffer = _queue.toList();

        List<List<int>> removedItems = buffer.getRange(index, index+howMany).toList();
        buffer.removeRange(index, index+howMany);

        if (values != null) {
            buffer.insert(index, values);
        }
        this._queue = Queue.from(buffer);

        return removedItems;

    }

    /// Replace item at 'index' with 'value'
    void replaceAt(int index, List<int> value) {
        List<List<int>> buffer = _queue.toList();
        buffer.removeAt(index);
        buffer.insert(index, value);
        _queue = Queue.from(buffer);
    }
}
