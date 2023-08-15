import 'dart:collection';
import 'dart:typed_data';

import 'package:dartsv/src/script/interpreter_v2.dart';

/// Utility class to represent the Script Interpreter Stack.
///
/// This class is used internally by the Script Interpreter, and should not really be useful in everyday wallet development.
class InterpreterStack <T> {
    List<T> _list = List<T>.empty(growable: true);

    InterpreterStack();

    /// Construct a stack instance from a Dart Queue
    ///
    /// Dart does not have a native representation for a Stack. This implementation
    /// wraps a Queue datastructure with the needed operations.
    /// Each element in the stack is represented as a byte buffer in the Queue.
    InterpreterStack.fromList(List<T> list){
        this._list = List<T>.from(list);
    }

    bool get isEmpty => _list.isEmpty;

    Iterable<T> get iterator => List.unmodifiable(_list);


    /// push an element onto the stack
    void push(T item) {
        _list.add(item);
    }

    /// get the height of the stack
    int get length => _list.length;

    /// remove all items from the stack
    void removeAll() {
        this._list.clear();
    }

    /// convenience method to create a copy of the stack
    InterpreterStack slice() {
        return InterpreterStack.fromList(_list);
    }

    /// Return the item at the specified index on the stack without modifying the stack
    ///
    /// `index` - a negative number specifying how deep into the stack we want to "peek"
    T peek({int index = -1}) {
        if (index > 0) {
            throw new StackOverflowError();
        }

        if (index > _list.length - 1) {
            throw new Exception("Can't peek past the first element");
        }
        return _list[_list.length + index];
    }

    /// Remove the item at the top of the stack and return it as a byte buffer
    T pop() {
        return _list.removeLast();
    }

    /// Removes items from the stack and optionally inserts new values
    ///
    /// `index` - starting index for items to be removed
    ///
    /// `howMany` - the number of items to be removed
    ///
    /// `values`  - an optional List of new items to add to the stack, or null if no items need insertion
    List<T> splice(int index, int howMany, {T? values}) {
        List<T> buffer = _list.toList();

        List<T> removedItems = buffer.getRange(index, index+howMany).toList();
        buffer.removeRange(index, index+howMany);

        if (values != null) {
            buffer.insert(index, values);
        }
        this._list = List<T>.from(buffer);

        return removedItems;

    }

    /// Replace item at 'index' with 'value'
    void replaceAt(int index, T value) {
        List<T> buffer = _list.toList();
        buffer.removeAt(index);
        buffer.insert(index, value);
        _list = List<T>.from(buffer);
    }

  bool contains(T item) {
        return _list.contains(item);

  }

  void add(T item) {
    push(item);
  }

  T getLast() => _list.last;

  T pollLast() {
      return _list.removeLast();
  }

  int size() {
      return _list.length;
  }

  void set(int index, T item) {
      _list[index] = item;
  }

  T getFirst() {
    return _list.first;
  }

  T pollFirst() {
    return _list.removeAt(0);
  }

  Iterator<T> descendingIterator() {
    return _list.reversed.iterator;
  }

  T getAt(int index) {
    return _list[index];
  }

  String toString(){
    return _list.fold("", (previousValue, element) => " ${previousValue} ${element}");
  }


    /**
     * Copy the element at index to top of stack
     */
  void copyToTop(int index) {
    add(_list[index]);
  }

    /**
     * Move the element at index to top of the stack
     */
  void moveToTop(int index) {
    var item = _list.removeAt(index);
    _list.add(item);
  }


}

