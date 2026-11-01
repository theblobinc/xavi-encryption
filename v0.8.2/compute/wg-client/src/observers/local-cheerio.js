import * as cheerio from 'cheerio';
import { DETERMINISTIC_OBSERVER_CATALOG } from './catalog.js';

const clean = value => String(value ?? '').replace(/\s+/g, ' ').trim();
const cap = (value, max = 20000) => clean(value).slice(0, Math.max(0, max));
const uniq = values => [...new Set(values.filter(Boolean))];

function absoluteUrl(value, baseUrl) {
  if (!value) return null;
  try { return baseUrl ? new URL(value, baseUrl).href : String(value); } catch { return String(value); }
}

function attrsOf($, node) {
  const out = {};
  for (const [key, value] of Object.entries(node?.attribs || {})) out[key] = String(value);
  return out;
}

export class CheerioEvidenceExtractor {
  constructor({maxTextChars=50000,maxItems=256}={}) {
    this.maxTextChars=Math.max(1000,Number(maxTextChars)||50000);
    this.maxItems=Math.max(8,Number(maxItems)||256);
  }

  extract(context={}) {
    const html=context.html ?? context.xml ?? context.document ?? context.text;
    if (typeof html !== 'string') throw new TypeError('Cheerio observer requires html/xml/document/text string');
    const baseUrl=context.baseUrl || context.url || null;
    const xmlMode=Boolean(context.xmlMode || context.xml);
    const $=cheerio.load(html,{xml:xmlMode?{}:undefined},!xmlMode);
    const maxItems=Math.min(this.maxItems,Math.max(1,Number(context.maxItems)||this.maxItems));
    const selector=context.selector ? String(context.selector) : null;

    if (selector) {
      const matches=[];
      $(selector).slice(0,maxItems).each((index,node)=>{
        const el=$(node);
        matches.push({
          index,
          tagName:String(node?.tagName || node?.name || ''),
          text:cap(el.text(),Number(context.maxMatchTextChars)||4000),
          html:context.includeHtml===false?undefined:String(el.html() ?? '').slice(0,Number(context.maxMatchHtmlChars)||8000),
          attributes:attrsOf($,node),
        });
      });
      return {schema:'xavi-cheerio-evidence/v1',mode:'query',selector,count:matches.length,matches};
    }

    const headings=[];
    $('h1,h2,h3,h4,h5,h6').slice(0,maxItems).each((_,node)=>{
      headings.push({level:Number(String(node.tagName).slice(1))||null,text:cap($(node).text(),1000),id:$(node).attr('id')||null});
    });
    const links=[];
    $('a[href]').slice(0,maxItems).each((_,node)=>{
      const el=$(node); const href=el.attr('href');
      links.push({text:cap(el.text(),1000),href:absoluteUrl(href,baseUrl),rel:el.attr('rel')||null});
    });
    const images=[];
    $('img').slice(0,maxItems).each((_,node)=>{
      const el=$(node);
      images.push({src:absoluteUrl(el.attr('src'),baseUrl),alt:cap(el.attr('alt'),1000),title:cap(el.attr('title'),1000)||null});
    });
    const jsonLd=[];
    $('script[type="application/ld+json"]').slice(0,Math.min(maxItems,32)).each((_,node)=>{
      const raw=$(node).text().trim();
      try { jsonLd.push({ok:true,value:JSON.parse(raw)}); } catch { jsonLd.push({ok:false,text:raw.slice(0,10000)}); }
    });
    const metadata={
      title:cap($('title').first().text(),2000)||null,
      language:$('html').attr('lang')||null,
      description:cap($('meta[name="description"]').attr('content'),4000)||null,
      canonical:absoluteUrl($('link[rel="canonical"]').attr('href'),baseUrl),
      author:cap($('meta[name="author"]').attr('content'),2000)||null,
      ogTitle:cap($('meta[property="og:title"]').attr('content'),2000)||null,
      ogDescription:cap($('meta[property="og:description"]').attr('content'),4000)||null,
      ogType:cap($('meta[property="og:type"]').attr('content'),1000)||null,
    };
    const clone=$.root().clone();
    clone.find('script,style,noscript,template').remove();
    const bodyText=cap(clone.find('body').length?clone.find('body').text():clone.text(),Number(context.maxTextChars)||this.maxTextChars);
    return {
      schema:'xavi-cheerio-evidence/v1',mode:'extract',metadata,headings,links,images,jsonLd,
      text:bodyText,
      counts:{headings:headings.length,links:links.length,images:images.length,jsonLd:jsonLd.length},
      fingerprints:{linkTargets:uniq(links.map(v=>v.href)).length},
    };
  }
}

export function registerCheerioObserver(xavi,{prior=2,retainOutput=false,timeoutMs=1500,metadata={}}={}) {
  if (!xavi?.observers) throw new TypeError('XaviBrowser observer registry required');
  const spec=DETERMINISTIC_OBSERVER_CATALOG.cheerio;
  const extractor=new CheerioEvidenceExtractor();
  const descriptor=xavi.observers.register({
    id:'local-cheerio',modelId:'cheeriojs/cheerio',revision:'npm:1.2.0',license:spec.license,runtime:'cheerio-1.2.0',
    capabilities:spec.capabilities,modalities:spec.modalities,prior,retainOutput,timeoutMs,
    metadata:{deterministic:true,costClass:spec.costClass,networkRequired:false,evidenceClass:'structured-extraction',...metadata},
    run:(context)=>extractor.extract(context),
  });
  return {descriptor,extractor};
}
