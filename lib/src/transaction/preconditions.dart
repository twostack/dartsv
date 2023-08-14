

import 'package:dartsv/dartsv.dart';

class PreConditions {
  static assertTrue(bool expression) {
    if (!expression) {
      throw new IllegalArgumentException("");
    }
  }

  static assertTrueWithMessage(bool expression, String errorMessage) {
    if (!expression) {
      throw new IllegalArgumentException(errorMessage);
    }
  }
}
