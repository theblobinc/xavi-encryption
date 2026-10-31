export { KnowledgeCorpus } from './knowledge.js';
export { LexicalFaculty } from './lexical.js';
export { TranslationFaculty } from './translation.js';
export { MathFaculty } from './math.js';
export { SecurityFaculty, BrowserSecurityFaculty, SecurityMonitor } from './security.js';
export { AdPolicyFaculty } from './ads.js';
export { LexiconFaculty } from './lexicon.js';
export { LanguageFaculty } from './language.js';

import { KnowledgeCorpus } from './knowledge.js';
import { LexicalFaculty } from './lexical.js';
import { TranslationFaculty } from './translation.js';
import { MathFaculty } from './math.js';
import { BrowserSecurityFaculty, SecurityMonitor } from './security.js';
import { AdPolicyFaculty } from './ads.js';
import { LexiconFaculty } from './lexicon.js';
import { LanguageFaculty } from './language.js';
export function createBrowserFaculties(xavi){return{knowledge:new KnowledgeCorpus(xavi),lexical:new LexicalFaculty(),translation:new TranslationFaculty(),math:new MathFaculty(xavi),security:new BrowserSecurityFaculty(xavi),ads:new AdPolicyFaculty(xavi),lexicon:new LexiconFaculty(xavi),language:new LanguageFaculty(xavi),securityMonitor:options=>new SecurityMonitor(new BrowserSecurityFaculty(xavi),options)};}
