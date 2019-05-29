import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.GroovyEventFilterOptions;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.Normalized;

Boolean hasNormalizedType(Event e, Normalized.Type n) {
  return e?.getNormalized()?.isOfType(n);
}

Boolean httpRequest(Event e, GroovyEventFilterOptions efOpt) {
  if (!hasNormalizedType(e, Normalized.Type.HTTP_REQUEST)) {
    return false;
  }

  return true;
}
