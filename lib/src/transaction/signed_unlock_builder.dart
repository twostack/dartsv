
import '../../dartsv.dart';

abstract class SignedUnlockBuilder {
  List<SVSignature> get signatures;
  set signatures(List<SVSignature> value);
}
