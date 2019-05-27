import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.OpenSSH;
import com.mozilla.secops.parser.KeyedEvent;

void noop() {
}

int inc(int x) {
  return x + 1;
}

int add(int x, int y) {
  return x + y;
}

KeyedEvent eventHandler(Event input) {
  if (input.getPayloadType() != Payload.PayloadType.OPENSSH) {
    return null;
  }
  OpenSSH o = input.getPayload();
  if (o?.getUser() == "riker") {
    return new KeyedEvent(o.getUser(), input);
  }
  return null;
}
