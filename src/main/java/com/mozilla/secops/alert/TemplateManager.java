package com.mozilla.secops.alert;

import com.mozilla.secops.GcsUtil;
import freemarker.cache.ClassTemplateLoader;
import freemarker.cache.MultiTemplateLoader;
import freemarker.cache.TemplateLoader;
import freemarker.cache.URLTemplateLoader;
import freemarker.template.Configuration;
import freemarker.template.MalformedTemplateNameException;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import freemarker.template.TemplateNotFoundException;
import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Manager class for processing templates using Freemarker */
public class TemplateManager {
  private Configuration cfg;
  private final AlertConfiguration alertCfg;

  /**
   * Create processed template using supplied template name and template variables
   *
   * @param templateName Name of template file
   * @param variables Variables for template
   * @return Assembled template
   */
  public String processTemplate(String templateName, HashMap<String, Object> variables)
      throws IOException, MalformedTemplateNameException, TemplateException,
          TemplateNotFoundException {
    Template temp = cfg.getTemplate(templateName);
    Writer out = new StringWriter();
    temp.process(variables, out);
    return out.toString();
  }

  /* Extends URLTemplateLoader to support Google Cloud Storage URLs */
  private class GcsTemplateLoader extends URLTemplateLoader {
    private String basePath;
    private final Logger log;

    public GcsTemplateLoader(String basePath) {
      log = LoggerFactory.getLogger(GcsTemplateLoader.class);
      if (!basePath.endsWith("/")) {
        basePath = basePath + "/";
      }
      this.basePath = basePath;
    }

    protected java.net.URL getURL(String name) {
      try {
        return GcsUtil.signedUrlFromGcsUrl(String.format("%s%s", basePath, name));
      } catch (IllegalStateException exc) {
        log.error(
            "no implementation of ServiceAccountSigner was provided to StorageOptions: {}",
            exc.getMessage());
      } catch (IllegalArgumentException exc) {
        log.error("there was an error with the SignUrlOptions: {}", exc.getMessage());
      } catch (com.google.auth.ServiceAccountSigner.SigningException exc) {
        log.error("the attempt to sign the URL failed: {}", exc.getMessage());
      }
      return null;
    }
  }

  /** Construct new template manager object */
  public TemplateManager(AlertConfiguration alertCfg) {
    this.alertCfg = alertCfg;
    cfg = new Configuration(Configuration.VERSION_2_3_28);
    cfg.setDefaultEncoding("UTF-8");
    cfg.setLogTemplateExceptions(false);
    cfg.setWrapUncheckedExceptions(true);
    cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);

    ClassTemplateLoader ctl = new ClassTemplateLoader(TemplateManager.class, "/alerts/templates");
    if (alertCfg.getGcsTemplateBasePath() != null) {
      GcsTemplateLoader gtl = new GcsTemplateLoader(alertCfg.getGcsTemplateBasePath());
      MultiTemplateLoader mtl = new MultiTemplateLoader(new TemplateLoader[] {gtl, ctl});
      cfg.setTemplateLoader(mtl);
    } else {
      cfg.setTemplateLoader(ctl);
    }
  }
}
