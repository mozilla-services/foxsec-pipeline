package com.mozilla.secops.alert;

/**
 * AlertCompat contains a set of helper functions meant for ensuring reverse compatibility in alert
 * formats
 */
public class AlertCompat {
  private static Alert historicalSubcategories(Alert a) {
    // Alert previously did not have a dedicated subcategory field, and it was up to a given
    // pipeline to decide which field to use as a subcategory. This caused issues with downstream
    // processing as Alert consumers needed to be aware of what type of alert it was in order to
    // select the correct subcategory field.
    //
    // This was changed to use a dedicated subcategory field; this function adjusts the alert object
    // to maintain compatibility with older alert formats for affected pipelines. If the historical
    // subcategory field is missing, add it based on the dedicated field. If the dedicated field is
    // missing but the historical field is not, set the dedicated field to the historical field
    // value.
    String c = a.getCategory();
    String subcat = a.getSubcategory();
    String hist_subcat = null;
    String set_hist_subcat = null;

    if (c == null) {
      return a;
    }

    if (c.equals("amo")) {
      hist_subcat = "amo_category";
      set_hist_subcat = a.getMetadataValue(hist_subcat);
    } else if (c.equals("customs")) {
      hist_subcat = "customs_category";
      set_hist_subcat = a.getMetadataValue(hist_subcat);
    } else {
      return a;
    }

    if (subcat == null && set_hist_subcat != null) {
      a.setSubcategory(set_hist_subcat);
    } else if (subcat != null && set_hist_subcat == null) {
      a.addMetadata(hist_subcat, subcat);
    }

    return a;
  }

  public static Alert compatibility(Alert a) {
    return historicalSubcategories(a);
  }
}
