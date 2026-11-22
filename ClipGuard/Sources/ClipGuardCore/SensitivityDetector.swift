import Foundation

/// 敏感内容类别
public enum SensitivityKind: String, Codable, CaseIterable, Sendable {
    case bankCard        // 银行卡号（Luhn 校验）
    case privateKey      // PEM / JWK / 长十六进制私钥
    case mnemonic        // BIP39 助记词
    case apiToken        // 各类 API Token / JWT
    case password        // 高熵口令 / 中文密码短语
    case oneTimeCode     // 6 位验证码（默认关闭，误报较多）

    public var label: String {
        switch self {
        case .bankCard:   return "银行卡号"
        case .privateKey: return "私钥"
        case .mnemonic:   return "助记词"
        case .apiToken:   return "API 令牌"
        case .password:   return "口令"
        case .oneTimeCode: return "验证码"
        }
    }
}

/// 一次敏感内容识别结果
public struct SensitivityResult: Equatable, Sendable {
    public let kind: SensitivityKind
    /// 0.0 ~ 1.0，多规则命中时取最大值
    public let confidence: Double
    /// 脱敏后的预览，可安全写日志 / 上屏
    public let preview: String

    public init(kind: SensitivityKind, confidence: Double, preview: String) {
        self.kind = kind
        self.confidence = min(1.0, max(0.0, confidence))
        self.preview = preview
    }
}

/// 检测器开关。默认只打开误报率低的类别。
public struct DetectorConfig: Codable, Equatable, Sendable {
    public var detectBankCard: Bool
    public var detectPrivateKey: Bool
    public var detectMnemonic: Bool
    public var detectApiToken: Bool
    public var detectPassword: Bool
    public var detectOneTimeCode: Bool
    /// 超过该置信度才返回结果
    public var minimumConfidence: Double

    public init(
        detectBankCard: Bool = true,
        detectPrivateKey: Bool = true,
        detectMnemonic: Bool = true,
        detectApiToken: Bool = true,
        detectPassword: Bool = true,
        detectOneTimeCode: Bool = false,
        minimumConfidence: Double = 0.6
    ) {
        self.detectBankCard = detectBankCard
        self.detectPrivateKey = detectPrivateKey
        self.detectMnemonic = detectMnemonic
        self.detectApiToken = detectApiToken
        self.detectPassword = detectPassword
        self.detectOneTimeCode = detectOneTimeCode
        self.minimumConfidence = minimumConfidence
    }
}

/// 敏感内容识别器（纯逻辑，无 AppKit 依赖，可在 Linux 单测中运行）
public struct SensitivityDetector: Sendable {
    public var config: DetectorConfig

    public init(config: DetectorConfig = .init()) { self.config = config }

    /// 分析一段剪贴板文本；非敏感返回 nil
    public func analyze(_ text: String) -> SensitivityResult? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != ClipGuardMeta.placeholder else { return nil }
        // 单字符内容不可能是敏感信息，顺带挡住表情、单个汉字等
        guard trimmed.count >= 4 else { return nil }

        var hits: [SensitivityResult] = []
        if config.detectBankCard, let r = Self.detectBankCard(trimmed) { hits.append(r) }
        if config.detectPrivateKey, let r = Self.detectPrivateKey(trimmed) { hits.append(r) }
        if config.detectMnemonic, let r = Self.detectMnemonic(trimmed) { hits.append(r) }
        if config.detectApiToken, let r = Self.detectApiToken(trimmed) { hits.append(r) }
        if config.detectPassword, let r = Self.detectPassword(trimmed) { hits.append(r) }
        if config.detectOneTimeCode, let r = Self.detectOneTimeCode(trimmed) { hits.append(r) }

        guard let best = hits.max(by: { $0.confidence < $1.confidence }),
              best.confidence >= config.minimumConfidence else { return nil }
        return best
    }

    // MARK: - 银行卡号（Luhn）

    static func detectBankCard(_ text: String) -> SensitivityResult? {
        // 允许空格 / 连字符分组，13~19 位（含分隔符长度放宽）
        let digits = text.filter { $0.isNumber }
        guard (13...19).contains(digits.count) else { return nil }
        // 文本里数字应占主导，避免把长文档里的数字串误判
        let digitRatio = Double(digits.count) / Double(text.filter { !$0.isWhitespace }.count)
        guard digitRatio > 0.85 else { return nil }
        guard luhnValid(digits) else { return nil }
        // 11 位且以 1 开头是手机号，不是卡号
        if digits.count == 11, digits.hasPrefix("1") { return nil }
        return SensitivityResult(
            kind: .bankCard, confidence: 0.95,
            preview: "银行卡号 \(mask(digits, visiblePrefix: 4, visibleSuffix: 4))"
        )
    }

    /// Luhn / Mod 10 校验
    public static func luhnValid(_ digits: String) -> Bool {
        var sum = 0
        let reversed = digits.reversed().map { Int($0.asciiValue! - 48) }
        for (index, digit) in reversed.enumerated() {
            var d = digit
            if index % 2 == 1 { d *= 2; if d > 9 { d -= 9 } }
            sum += d
        }
        return sum % 10 == 0
    }

    // MARK: - 私钥

    static func detectPrivateKey(_ text: String) -> SensitivityResult? {
        // 1) PEM 私钥块
        if text.contains("-----BEGIN") &&
           (text.contains("PRIVATE KEY-----") || text.contains("OPENSSH PRIVATE KEY-----")) {
            let kind = text.uppercased().contains("OPENSSH") ? "OpenSSH" :
                       text.uppercased().contains("RSA") ? "RSA" :
                       text.uppercased().contains("EC") ? "EC" : "PEM"
            return SensitivityResult(
                kind: .privateKey, confidence: 0.99,
                preview: "\(kind) 私钥（\(mask(text, visiblePrefix: 10, visibleSuffix: 0))…）"
            )
        }
        // 2) JWK（含 d 参数）
        if let data = text.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           obj["kty"] != nil, obj["d"] != nil {
            return SensitivityResult(kind: .privateKey, confidence: 0.95,
                                     preview: "JWK 私钥（含 d 参数）")
        }
        // 3) OpenSSH 单行私钥
        if text.hasPrefix("ssh-") || text.hasPrefix("sk-ssh-") || text.hasPrefix("ecdsa-") {
            return SensitivityResult(kind: .privateKey, confidence: 0.9,
                                     preview: "SSH 私钥材料 \(mask(text, visiblePrefix: 7, visibleSuffix: 0))…")
        }
        // 4) 裸十六进制：32 字节(64)/20 字节(40，BTC WIF 候选)，整串仅十六进制字符
        let compact = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if (compact.count == 64 || compact.count == 40),
           compact.unicodeScalars.allSatisfy({ Self.hexAlphabet.contains($0) }) {
            return SensitivityResult(
                kind: .privateKey, confidence: 0.8,
                preview: "十六进制私钥候选 \(mask(compact, visiblePrefix: 6, visibleSuffix: 4))"
            )
        }
        // 5) WIF：5 / K / L 开头，Base58，长度 51~52
        if (compact.hasPrefix("5") || compact.hasPrefix("K") || compact.hasPrefix("L")),
           (51...52).contains(compact.count),
           compact.unicodeScalars.allSatisfy({ Self.base58Alphabet.contains($0) }) {
            return SensitivityResult(kind: .privateKey, confidence: 0.85,
                                     preview: "WIF 私钥候选 \(mask(compact, visiblePrefix: 4, visibleSuffix: 4))")
        }
        return nil
    }

    private static let base58Alphabet = Set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".unicodeScalars)
    private static let hexAlphabet = Set("0123456789abcdefABCDEF".unicodeScalars)

    // MARK: - BIP39 助记词

    static func detectMnemonic(_ text: String) -> SensitivityResult? {
        let words = text.lowercased()
            .components(separatedBy: CharacterSet.letters.inverted)
            .filter { !$0.isEmpty }
        guard words.count >= 12 else { return nil }
        // 按总词次统计（标准测试向量里常有重复词，如 11 个 abandon + about）
        let hitTokens = words.filter { bip39Sample.contains($0) }.count
        let distinctRatio = Double(Set(words).filter { bip39Sample.contains($0) }.count)
            / Double(max(1, Set(words).count))
        // 词表命中率 >= 80% 且不同词也大多落在词表内，避免普通英文句子误报
        guard Double(hitTokens) / Double(words.count) >= 0.8,
              distinctRatio >= 0.6 else { return nil }
        return SensitivityResult(
            kind: .mnemonic, confidence: 0.9,
            preview: "BIP39 助记词（\(words.count) 词，首词 \(words.first ?? "?")…）"
        )
    }

    // 内置常用 BIP39 词表样本（完整 2048 词的高频率子集；覆盖演示与多数真实助记词）
    static let bip39Sample: Set<String> = [
        "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
        "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
        "action","actor","actress","actual","adapt","add","addict","address","adjust","admit",
        "adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent",
        "agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert",
        "alien","all","alley","allow","almost","alone","alpha","already","also","alter",
        "always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger",
        "angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique",
        "anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic",
        "area","arena","argue","arm","armed","armor","army","around","arrange","arrest",
        "arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset",
        "assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction",
        "audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake",
        "aware","away","awesome","awful","awkward","axis","baby","bachelor","bacon","badge",
        "bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain",
        "barrel","base","basic","basket","battle","beach","bean","beauty","because","become",
        "beef","before","begin","behave","behind","believe","below","belt","bench","benefit",
        "best","betray","better","between","beyond","bicycle","bid","bike","bind","biology",
        "bird","birth","bitter","black","blade","blame","blank","blast","bleak","bless",
        "blind","blood","blossom","blow","blue","blur","blush","board","boat","body",
        "boil","bomb","bone","bonus","book","boost","border","boring","borrow","boss",
        "bottom","bounce","box","boy","bracket","brain","brand","brass","brave","bread",
        "breeze","brick","bridge","brief","bright","bring","brisk","broccoli","broken","bronze",
        "broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb",
        "bulk","bullet","bundle","bunny","burden","burger","burst","bus","business","busy",
        "butter","buyer","buzz","cabbage","cabin","cable","cactus","cage","cake","call",
        "calm","camera","camp","can","canal","cancel","candy","cannon","canoe","canvas",
        "canyon","cap","capital","captain","car","carbon","card","cargo","carpet","carry",
        "cart","case","cash","casino","castle","casual","cat","catalog","catch","category",
        "cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century",
        "cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase",
        "cheap","check","cheese","chef","cherry","chest","chicken","chief","child","chimney",
        "choice","choose","chronic","chuckle","chunk","churn","citizen","city","civil","claim",
        "clap","clarify","claw","clay","clean","clerk","clever","click","client","cliff",
        "climb","clinic","clip","clock","clog","close","cloth","cloud","clown","club",
        "clump","cluster","clutch","coach","coast","coconut","code","coffee","coil","coin",
        "collect","color","column","combine","come","comfort","comic","common","company","concert",
        "conduct","confirm","congress","connect","consider","control","cook","cool","copper","copy",
        "coral","core","corn","correct","cost","cotton","couch","country","couple","course",
        "cousin","cover","coyote","crack","cradle","craft","cram","crane","crash","crater",
        "crawl","crazy","cream","credit","creek","crew","cricket","crime","crisp","critic",
        "crop","cross","crouch","crowd","crucial","cruel","cruise","crumble","crush","cry",
        "crystal","cube","culture","cup","cupboard","curious","current","curtain","curve","cushion",
        "custom","cute","cycle","dad","damage","damp","dance","danger","daring","dash",
        "daughter","dawn","day","deal","debate","debris","decade","december","decide","decline",
        "decorate","decrease","deer","defense","define","defy","degree","delay","deliver","demand",
        "demise","denial","dentist","deny","depart","depend","deposit","depth","deputy","derive",
        "describe","desert","design","desk","despair","destroy","detail","detect","develop","device",
        "devote","diagram","dial","diamond","diary","dice","diesel","diet","differ","digital",
        "dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover","disease","dish",
        "dismiss","disorder","display","distance","divert","divide","divorce","dizzy","doctor","document",
        "dog","doll","dolphin","domain","donate","donkey","donor","door","dose","double",
        "dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drill",
        "drink","drip","drive","drop","drum","dry","duck","dumb","dune","during",
        "dust","dutch","duty","dwarf","dynamic","eager","eagle","early","earn","earth",
        "easily","east","easy","echo","ecology","economy","edge","edit","educate","effort",
        "egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator",
        "elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty",
        "enable","enact","end","endless","endorse","enemy","energy","enforce","engage","engine",
        "enhance","enjoy","enlist","enough","enrich","enroll","ensure","enter","entire","entry",
        "envelope","episode","equal","equip","era","erase","erode","erosion","error","erupt",
        "escape","essay","essence","estate","eternal","ethics","evidence","evil","evoke","evolve",
        "exact","example","excess","exchange","excite","exclude","excuse","execute","exercise","exhaust",
        "exhibit","exile","exist","exit","exotic","expand","expect","expire","explain","expose",
        "express","extend","extra","eye","eyebrow","fabric","face","faculty","fade","faint",
        "faith","fall","false","fame","family","famous","fan","fancy","fantasy","farm",
        "fashion","fat","fatal","father","fatigue","fault","favorite","feature","february","federal",
        "fee","feed","feel","female","fence","festival","fetch","fever","few","fiber",
        "fiction","field","figure","file","film","filter","final","find","fine","finger",
        "finish","fire","firm","fiscal","fish","fit","fitness","fix","flag","flame",
        "flash","flat","flavor","flee","flight","flip","float","flock","floor","flower",
        "fluid","flush","fly","foam","focus","fog","foil","fold","follow","food",
        "foot","force","forest","forget","fork","fortune","forum","forward","fossil","foster",
        "found","fox","fragile","frame","frequent","fresh","friend","fringe","frog","front",
        "frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury","future",
        "gadget","gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic",
        "garment","gas","gasp","gate","gather","gauge","gaze","general","genius","genre",
        "gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl",
        "give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory",
        "glove","glow","glue","goat","goddess","gold","good","goose","gorilla","gospel",
        "gossip","govern","gown","grab","grace","grain","grant","grape","grass","gravity",
        "great","green","grid","grief","grit","grocery","group","grow","grit","guard",
        "guess","guide","guilt","guitar","gun","gym","habit","hair","half","hammer",
        "hamster","hand","happy","harbor","hard","harsh","harvest","hat","have","hawk",
        "hazard","head","health","heart","heavy","hedgehog","height","hello","helmet","help",
        "hen","hero","hide","high","hill","hint","hip","hire","history","hobby",
        "hockey","hold","hole","holiday","hollow","home","honey","hood","hope","horn",
        "horse","hospital","host","hotel","hour","hover","hub","huge","human","humble",
        "humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice",
        "icon","idea","identify","idle","ignore","ill","illegal","illness","image","imitate",
        "immense","immune","impact","impose","improve","impulse","inch","include","income","increase",
        "index","indicate","indoor","industry","infant","inflict","inform","inhale","inherit","initial",
        "inject","inmate","inner","innocent","input","inquiry","insane","insect","inside","inspire",
        "install","intact","interest","into","invest","invite","involve","iron","island","isolate",
        "issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly",
        "jewel","job","join","joke","journey","joy","judge","juice","jump","jungle",
        "junior","junk","just","kangaroo","keen","keep","ketchup","key","kick","kid",
        "kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi","knee",
        "knife","knock","know","lab","label","labor","ladder","lady","lake","lamp",
        "language","laptop","large","later","latin","laugh","laundry","lava","law","lawn",
        "lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","led","left",
        "leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson",
        "letter","level","liberty","library","license","life","lift","light","like","limb",
        "limit","link","lion","liquid","list","little","live","lizard","load","loan",
        "lobster","local","lock","logic","lonely","long","loop","lottery","loud","lounge",
        "love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine",
        "mad","magic","magnet","maid","mail","main","major","make","mammal","man",
        "manage","mandate","mango","mansion","manual","maple","marble","march","margin","marine",
        "market","marriage","mask","mass","master","match","material","math","matrix","matter",
        "maximum","meadow","meaning","measure","meat","mechanic","medal","media","melody","melt",
        "member","memory","mention","menu","mercy","merge","merit","merry","mesh","message",
        "metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor",
        "minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile",
        "model","modify","mom","moment","monitor","monkey","monster","month","moon","moral",
        "more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie",
        "much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual",
        "myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature",
        "near","neck","need","negative","neglect","neither","nephew","nerve","nest","net",
        "network","neutral","never","news","next","nice","night","noble","noise","nominee",
        "noodle","normal","north","nose","notable","nothing","notice","novel","now","nuclear",
        "number","nurse","nut","nylon","oak","obey","object","oblige","obscure","observe",
        "obtain","obvious","occur","ocean","october","odor","off","offer","office","often",
        "oil","okay","old","olive","olympic","omit","once","one","onion","online",
        "only","open","opera","opinion","oppose","option","orange","orbit","orchard","order",
        "ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output",
        "outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact",
        "paddle","page","pair","palace","palm","panda","panel","panic","panther","paper",
        "parade","parent","park","parrot","party","pass","patch","path","patient","patrol",
        "pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen",
        "penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo",
        "phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot",
        "pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate",
        "play","please","pledge","pluck","plug","plunge","poem","poet","point","polar",
        "pole","police","pond","pony","pool","popular","portion","position","possible","post",
        "potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare",
        "present","pretty","prevent","price","pride","primary","print","priority","prison","private",
        "prize","problem","process","produce","profit","program","project","promote","proof","property",
        "prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin",
        "punch","pupil","puppy","purchase","purity","purpose","purse","push","puzzle","pyramid",
        "quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit","raccoon",
        "race","rack","radar","radio","rage","rail","rain","raise","rally","ramp",
        "ranch","random","range","rapid","rare","rate","rather","raven","raw","razor",
        "ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle",
        "reduce","reflect","reform","region","regret","regular","reject","relax","release","relief",
        "rely","remain","remember","remind","remove","render","renew","rent","reopen","repair",
        "repeat","replace","report","require","rescue","resemble","resist","resource","response","result",
        "retire","retreat","return","reunion","reveal","review","reward","rhythm","rib","ribbon",
        "rice","rich","ride","ridge","rifle","right","rigid","ring","riot","ripple",
        "risk","ritual","rival","river","road","roast","robot","robust","rocket","romance",
        "roof","rookie","room","rose","rotate","rough","round","route","royal","rubber",
        "rude","rug","rule","run","runway","rural","sad","saddle","sadness","safe",
        "sail","salad","salmon","salon","salt","salute","same","sample","sand","satisfy",
        "satoshi","sauce","sausage","save","say","scale","scan","scar","scare","scatter",
        "scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script",
        "scrub","sea","search","season","seat","second","secret","section","security","seed",
        "seek","segment","select","sell","seminar","senior","sense","sentence","series","service",
        "session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell",
        "sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop",
        "short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side",
        "siege","sight","sign","silent","silk","silly","silver","similar","simple","since",
        "sing","siren","sister","situate","six","size","skate","sketch","ski","skill",
        "skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight",
        "slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth",
        "snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda",
        "soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry",
        "sort","soul","sound","soup","source","south","space","spare","spatial","spawn",
        "speak","special","species","specific","speech","speed","spell","spend","sphere","spice",
        "spider","spike","spin","spirit","split","sponsor","spoon","sport","spot","spray",
        "spread","spring","spy","square","squeeze","squirrel","stable","stadium","staff","stage",
        "stairs","stamp","stand","start","state","stay","steak","steel","stem","step",
        "stereo","stick","still","sting","stock","stomach","stone","stool","story","stove",
        "strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject",
        "submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer",
        "sun","sunny","sunset","super","supply","supreme","sure","surface","surge","surprise",
        "surround","survey","survive","suspect","sustain","swallow","swamp","swap","swarm","swear",
        "sweet","swim","swing","switch","sword","symbol","symptom","syrup","system","table",
        "tackle","tag","tail","talent","talk","tank","tape","target","task","taste",
        "tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term",
        "test","text","thank","that","theme","then","theory","there","they","thing",
        "this","thought","three","thrive","throw","thumb","thunder","ticket","tide","tiger",
        "tilt","timber","time","tiny","tip","tired","tissue","title","toast","tobacco",
        "today","toddler","toe","together","toilet","token","tomato","tomorrow","tone","tongue",
        "tonight","tool","tooth","top","topic","topple","torch","tornado","tortoise","toss",
        "total","tourist","toward","tower","town","toy","track","trade","traffic","train",
        "transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe",
        "trick","trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet",
        "trunk","trust","truth","try","tube","tuna","tunnel","turkey","turn","turtle",
        "twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella",
        "unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform",
        "union","unique","unit","universe","unknown","unlock","until","unusual","unveil","update",
        "upgrade","uphold","upon","upper","upset","urban","urge","usage","use","used",
        "useful","useless","usual","utility","vacant","vacuum","vague","valid","valley","valve",
        "van","vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture",
        "venue","verb","verify","version","very","vessel","veteran","viable","vibrant","vicious",
        "victory","video","view","village","vintage","violin","virtual","virus","visa","visit",
        "visual","vital","vivid","vocal","voice","void","volcano","volume","vote","voyage",
        "wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior",
        "wash","wasp","waste","water","wave","way","wealth","weapon","wear","weasel",
        "weather","web","wedding","weekend","weird","welcome","well","west","wet","whale",
        "what","wheat","wheel","when","where","whip","whisper","wide","width","wife",
        "wild","will","win","window","wine","wing","wink","winner","winter","wire",
        "wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word",
        "work","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong",
        "yard","year","yellow","you","young","youth","zebra","zero","zone","zoo"
    ]

    // MARK: - API Token

    static func detectApiToken(_ text: String) -> SensitivityResult? {
        let compact = text.trimmingCharacters(in: .whitespacesAndNewlines)
        // 已知厂商前缀
        let patterns: [(String, String, Double)] = [
            ("sk-[A-Za-z0-9]{20,}", "OpenAI 风格密钥（sk-…）", 0.95),
            ("sk-ant-[A-Za-z0-9_\\-]{20,}", "Anthropic 风格密钥（sk-ant-…）", 0.95),
            ("gh[pousr]_[A-Za-z0-9]{30,}", "GitHub 令牌（gh*_…）", 0.95),
            ("AKIA[0-9A-Z]{16}", "AWS Access Key ID（AKIA…）", 0.95),
            ("xox[baprs]-[A-Za-z0-9-]{10,}", "Slack 令牌（xox…）", 0.95),
            ("rk_live_[A-Za-z0-9]{20,}", "Stripe 受限密钥（rk_live_…）", 0.95),
            ("AIza[0-9A-Za-z_\\-]{30,}", "Google API 密钥（AIza…）", 0.9),
            ("glpat-[A-Za-z0-9_\\-]{20}", "GitLab 令牌（glpat-…）", 0.9),
        ]
        for (pattern, label, conf) in patterns {
            if firstMatch(pattern, in: compact) != nil {
                return SensitivityResult(kind: .apiToken, confidence: conf,
                                         preview: label + " " + mask(compact, visiblePrefix: 6, visibleSuffix: 3))
            }
        }
        // JWT：三段 Base64URL，以 eyJ 开头（header 为 {"alg"…）
        if let r = firstMatch(#"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"#, in: compact) {
            return SensitivityResult(kind: .apiToken, confidence: 0.9,
                                     preview: "JWT 令牌 \(mask(r, visiblePrefix: 8, visibleSuffix: 0))…")
        }
        // 通用高熵令牌：>=32 位的 Base64/URL-safe 串，且数字+大小写字母三类齐全
        if let r = firstMatch(#"[A-Za-z0-9+/_\-]{32,}={0,2}"#, in: compact),
           r.contains(where: { $0.isNumber }),
           r.contains(where: { $0.isUppercase }),
           r.contains(where: { $0.isLowercase }) {
            return SensitivityResult(kind: .apiToken, confidence: 0.6,
                                     preview: "高熵令牌候选 \(mask(r, visiblePrefix: 4, visibleSuffix: 4))")
        }
        return nil
    }

    // MARK: - 口令

    static func detectPassword(_ text: String) -> SensitivityResult? {
        let compact = text.trimmingCharacters(in: .whitespacesAndNewlines)
        // 不含空白的单 token 口令
        if !compact.contains(where: { $0.isWhitespace }), compact.count >= 8, compact.count <= 128 {
            let hasLower = compact.contains { $0.isLowercase }
            let hasUpper = compact.contains { $0.isUppercase }
            let hasDigit = compact.contains { $0.isNumber }
            let hasSymbol = compact.contains { !$0.isLetter && !$0.isNumber }
            let classes = [hasLower, hasUpper, hasDigit, hasSymbol].filter { $0 }.count
            if classes >= 3 {
                return SensitivityResult(
                    kind: .password,
                    confidence: compact.count >= 12 ? 0.75 : 0.62,
                    preview: "高熵口令（\(compact.count) 位，\(classes) 类字符）\(mask(compact, visiblePrefix: 1, visibleSuffix: 1))"
                )
            }
        }
        // 中文密码短语：含汉字且同时带数字/符号（纯中文短句与口令无法区分，
        // 为不影响日常中文复制，只对混合形态报警，宁可漏报不误报）
        let cjkCount = compact.unicodeScalars.filter {
            (0x4E00...0x9FFF).contains($0.value) || (0x3400...0x4DBF).contains($0.value)
        }.count
        let hasAsciiDigit = compact.contains { $0.isASCII && $0.isNumber }
        // 注意：不能用 isNumber 判断——"一""三"等汉字数字 isNumber 也为 true
        let hasSymbol = compact.contains { !$0.isLetter && !$0.isWhitespace }
        if cjkCount >= 2, cjkCount <= 16, compact.count <= 32,
           hasAsciiDigit || hasSymbol {
            return SensitivityResult(kind: .password, confidence: 0.72,
                                     preview: "中文混合密码（\(cjkCount) 个汉字 + 数字/符号）")
        }
        // 空格分隔的短密码短语（3~6 词，每词 >=3 字母），如 correct horse battery staple
        let words = compact.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
        if (3...6).contains(words.count),
           words.allSatisfy({ $0.count >= 3 && $0.unicodeScalars.allSatisfy { CharacterSet.letters.contains($0) } }) {
            return SensitivityResult(kind: .password, confidence: 0.65,
                                     preview: "密码短语（\(words.count) 词，首词 \(words[0])…）")
        }
        return nil
    }

    // MARK: - 验证码（默认关闭）

    static func detectOneTimeCode(_ text: String) -> SensitivityResult? {
        let compact = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard compact.count == 6, compact.allSatisfy({ $0.isNumber }) else { return nil }
        return SensitivityResult(kind: .oneTimeCode, confidence: 0.65,
                                 preview: "6 位数字验证码 \(mask(compact, visiblePrefix: 0, visibleSuffix: 2))")
    }

    // MARK: - 工具

    /// 脱敏：保留前 prefix / 后 suffix 位，其余替换为 •
    public static func mask(_ text: String, visiblePrefix: Int, visibleSuffix: Int) -> String {
        let chars = Array(text)
        guard chars.count > visiblePrefix + visibleSuffix else {
            return String(repeating: "•", count: max(2, chars.count))
        }
        let head = String(chars.prefix(visiblePrefix))
        let tail = String(chars.suffix(visibleSuffix))
        let hidden = chars.count - visiblePrefix - visibleSuffix
        return head + String(repeating: "•", count: min(hidden, 12)) + tail
    }

    static func firstMatch(_ pattern: String, in text: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let m = regex.firstMatch(in: text, range: range),
              let r = Range(m.range, in: text) else { return nil }
        return String(text[r])
    }
}
