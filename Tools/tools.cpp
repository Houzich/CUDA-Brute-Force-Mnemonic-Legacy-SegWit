/**
  ******************************************************************************
  * @author		Anton Houzich
  * @version	V2.0.0
  * @date		28-April-2023
  * @mail		houzich_anton@mail.ru
  * discussion  https://t.me/BRUTE_FORCE_CRYPTO_WALLET
  ******************************************************************************
  */
#include "main.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <omp.h>
#include <set>
#include <random>
#include <fstream>
#include <filesystem>

#include "../BruteForceMnemonic/stdafx.h"
#include "tools.h"
#include "utils.h"
#include "base58.h"
#include "segwit_addr.h"
#include <crypto/sha256.h>




namespace tools {




	uint64_t getSeedForRandom()
	{
		std::random_device rd;
		uint64_t ret;
		*(uint32_t*)&ret = rd();
		*(uint32_t*)((uint32_t*)&ret + 1) = rd();
		return ret;
	}


	void generateRandomUint64Buffer(uint64_t* buff, size_t len) {
		uint64_t seed_random = getSeedForRandom();

		std::uniform_int_distribution<uint64_t> distr;
		std::mt19937_64 eng(seed_random);

		for (int i = 0; i < len; i++)
		{
			buff[i] = distr(eng);
		}

	}

	void sha256(uint8_t* dest, const uint8_t* src, size_t n) {
		CSHA256 hash;
		hash.Write(src, n);
		hash.Finalize(dest);
	}

	// 18 kB
	static const uint8_t mnemonic_words[2048][9] = { "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd","abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire","across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address","adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid","again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album","alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already","also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst","anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual","another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear","apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed","armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist","artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete","atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt","author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome","awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony","ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic","basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin","behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better","between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter","black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom","blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus","book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy","bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief","bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown","brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle","bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz","cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can","canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital","captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash","casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught","cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal","certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase","chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child","chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon","circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean","clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog","close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast","coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come","comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress","connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral","core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin","cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl","crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop","cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry","crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve","cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring","dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide","decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay","deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit","depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy","detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary","dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur","direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display","distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll","dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft","dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip","drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty","dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy","echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either","elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else","embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable","enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine","enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire","entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error","erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil","evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse","execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand","expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow","fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family","famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue","fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female","fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file","film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first","fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee","flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam","focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork","fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame","frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit","fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery","game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate","gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture","ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance","glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue","goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown","grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid","grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt","guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy","harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health","heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden","high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday","hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host","hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry","hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify","idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune","impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index","indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit","initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane","insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite","involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar","jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge","juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup","key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten","kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake","lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law","lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left","leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson","letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like","limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan","lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge","love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine","mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage","mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine","market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix","matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media","melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry","mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind","minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed","mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster","month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor","mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum","mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin","narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect","neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next","nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable","note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak","obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean","october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic","omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose","option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original","orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over","own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace","palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot","party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment","peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people","pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical","piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer","pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please","pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police","pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato","pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare","present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison","private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote","proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull","pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose","purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question","quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio","rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate","rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall","receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region","regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember","remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace","report", "require", "rescue", "resemble", "resist", "resource", "response", "result","retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib","ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple","risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance","roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber","rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail","salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi","sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme","school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub","sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek","segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service","session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell","sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop","short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side","siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since","sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin","skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim","slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack","snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar","soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul","sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special","speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split","spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square","squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand","start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still","sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street","strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit","subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun","sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise","surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear","sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system","table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste","tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test","text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this","thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt","timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today","toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue","tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss","total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic","train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial","tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly","trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey","turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical","ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair","unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until","unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge","usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague","valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle","velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel","veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage","violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice","void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall","walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave","way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird","welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip","whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink","winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder","wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist","write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone","zoo" };
	// 2kB
	static const uint8_t mnemonic_word_lengths[2048] = { 7,7,4,5,5,6,6,8,6,5,6,8,7,6,7,4,8,7,6,3,6,5,7,6,5,3,6,7,6,5,5,7,6,7,6,6,6,5,3,5,5,5,3,3,7,5,5,5,7,5,5,3,5,5,6,5,5,7,4,5,6,7,7,5,6,6,7,6,7,5,5,5,6,5,8,6,7,6,7,7,7,3,5,7,6,5,7,5,4,6,4,5,5,3,5,5,4,6,7,6,6,5,3,8,6,7,3,6,7,5,6,6,6,7,4,6,6,8,7,7,5,6,4,6,4,6,7,7,5,5,5,4,7,5,7,4,4,8,5,5,3,7,7,4,6,6,6,3,6,7,6,4,5,6,6,5,4,6,7,6,4,6,5,6,6,7,5,4,5,7,4,6,6,7,6,7,3,4,4,7,4,5,6,5,5,5,7,5,5,5,5,5,7,6,4,4,5,5,4,4,4,4,4,5,4,5,6,6,6,4,6,6,3,3,7,5,5,5,5,5,6,5,6,5,6,5,5,8,6,6,5,7,5,5,6,5,6,7,5,4,4,6,6,6,6,6,5,3,8,4,6,5,4,7,5,5,6,4,4,4,4,6,4,3,5,6,5,6,5,6,6,7,7,7,3,6,4,5,6,5,4,4,4,6,6,6,3,7,5,8,6,6,5,7,4,7,6,6,6,7,6,7,5,5,8,6,5,7,6,5,4,5,5,6,4,6,5,7,5,5,7,6,6,7,7,5,5,5,8,6,7,4,5,5,4,7,4,4,5,5,6,5,6,5,5,6,4,5,4,5,5,5,5,4,5,7,6,5,5,7,4,6,4,4,7,5,6,7,4,7,5,6,7,7,7,7,8,7,8,7,8,4,4,6,4,5,4,4,7,4,6,5,7,6,6,6,5,6,5,6,5,4,5,5,6,5,5,5,6,5,4,7,5,5,6,4,5,6,5,7,5,6,7,6,5,3,7,4,7,3,8,7,7,7,5,7,6,4,5,3,6,4,5,6,6,4,8,4,3,4,6,6,6,8,6,7,8,8,4,7,6,4,6,5,7,6,6,6,7,4,6,6,7,5,6,6,8,6,6,4,7,7,6,6,7,6,6,7,4,7,5,4,6,4,6,7,7,7,6,8,6,4,8,8,7,4,7,8,7,8,6,6,7,5,6,8,3,4,7,6,6,6,5,4,4,6,4,5,6,5,7,4,5,5,5,5,5,4,5,4,4,3,4,4,4,6,4,5,4,5,7,5,5,5,4,5,6,4,4,4,7,7,4,4,7,6,3,5,6,5,5,8,7,7,8,8,5,4,6,6,7,6,7,6,7,5,6,5,3,7,7,5,6,7,6,6,7,5,6,6,6,6,6,5,6,5,8,7,5,5,3,5,5,7,5,5,6,5,7,6,7,6,8,4,5,6,5,7,6,8,6,7,6,7,8,7,7,5,5,4,6,6,6,6,7,6,7,6,5,3,7,6,4,7,4,5,5,4,5,4,6,6,3,5,7,4,7,3,5,6,7,5,8,7,8,7,3,4,4,6,5,8,5,5,3,5,7,5,6,4,4,6,5,4,4,6,6,4,4,5,6,4,3,7,3,4,5,5,4,6,4,6,4,5,5,5,6,5,5,3,4,5,3,4,4,6,4,4,5,6,6,4,7,5,7,6,6,5,3,7,5,8,5,6,6,4,5,5,5,6,5,4,3,5,7,4,6,6,4,6,7,4,3,6,7,6,6,7,3,4,4,6,5,4,7,6,5,6,7,7,5,5,4,6,6,7,4,4,4,6,5,5,5,7,5,5,5,5,4,4,4,7,4,4,5,7,6,6,6,4,4,5,5,5,5,5,7,5,5,4,5,4,7,5,4,5,5,5,5,5,6,3,3,5,4,4,6,7,4,5,6,4,5,7,3,4,4,6,4,6,5,5,8,6,5,6,4,3,4,6,4,4,4,3,4,7,5,6,4,4,7,6,4,5,4,4,4,6,5,8,4,5,4,5,3,4,5,6,5,7,6,4,6,5,4,7,6,3,4,4,8,4,6,3,7,7,5,7,7,6,6,6,7,7,4,7,6,8,5,8,6,8,6,7,6,6,7,7,6,6,6,5,8,5,7,6,6,6,7,7,6,8,4,6,6,7,4,6,7,5,4,5,6,6,3,4,7,5,5,5,3,4,4,7,3,5,5,4,6,6,4,4,8,4,4,7,3,4,3,6,4,7,4,3,7,4,6,4,4,5,5,4,3,5,5,6,4,4,4,8,6,5,5,5,5,7,4,3,4,7,5,4,6,4,5,5,7,4,3,5,6,7,5,4,6,4,7,6,6,5,4,7,7,7,4,4,5,4,4,5,4,4,6,4,6,4,6,4,4,7,5,4,5,6,4,4,7,4,6,4,5,5,7,6,5,5,6,6,7,3,5,6,4,4,4,5,4,6,3,6,7,5,7,6,5,6,5,6,6,6,8,4,4,6,5,8,4,6,6,7,4,6,4,7,4,8,5,5,6,4,6,6,7,4,5,5,5,5,4,7,5,6,6,8,4,7,5,4,7,5,6,7,6,6,4,7,3,5,7,6,5,6,3,6,7,6,7,5,4,5,4,7,8,6,6,5,8,5,4,5,4,6,4,8,6,6,8,5,4,6,6,7,4,5,4,6,6,5,6,6,4,4,4,8,7,7,6,5,4,3,7,7,5,4,4,4,5,5,5,7,6,6,5,4,7,4,7,6,5,3,7,6,5,3,3,4,6,6,7,7,6,7,5,5,7,4,3,5,6,5,3,4,3,5,7,4,4,3,5,6,4,4,5,7,6,6,6,5,7,5,8,5,6,8,6,7,5,7,5,6,7,4,4,4,3,5,6,6,5,4,6,4,4,6,4,5,5,5,7,5,6,6,4,6,5,4,5,4,7,6,7,5,4,7,5,6,4,7,7,3,7,6,6,6,7,6,6,3,5,5,6,8,5,6,7,5,3,6,4,5,4,7,4,6,5,5,5,6,7,5,4,6,6,5,4,6,4,4,5,5,4,6,4,4,4,7,7,8,8,4,6,7,7,6,5,8,6,7,6,7,7,6,7,5,5,7,5,8,6,7,5,7,7,7,6,7,7,7,5,8,7,7,5,7,6,7,4,4,5,7,5,5,5,8,6,7,5,4,3,6,7,7,7,7,8,5,4,4,5,6,7,4,4,5,5,4,4,5,5,4,5,6,5,5,4,4,6,5,3,5,5,4,6,5,7,6,7,6,6,7,6,7,6,6,6,6,7,6,5,7,6,4,6,8,6,6,6,5,4,6,6,6,7,6,7,6,8,6,8,8,6,6,7,6,7,6,6,6,6,3,6,4,4,4,5,5,5,5,4,4,6,4,6,5,5,4,5,5,6,6,7,4,6,4,4,6,5,5,5,5,6,4,3,4,3,6,5,3,6,7,4,4,5,6,5,4,6,4,6,4,7,7,5,7,4,3,5,4,5,7,5,6,6,7,8,8,5,5,6,6,5,3,6,6,4,6,6,7,8,4,4,7,6,4,7,6,5,8,6,7,7,6,5,5,6,5,7,5,4,5,7,6,5,5,4,6,5,4,5,4,5,8,5,6,5,7,3,7,4,4,5,5,4,6,4,5,6,7,6,5,4,5,6,7,3,4,5,6,3,5,4,5,5,4,4,5,7,5,5,6,4,6,4,4,5,5,5,5,5,6,5,5,4,5,4,4,6,6,4,4,4,5,7,5,8,5,7,4,4,5,4,4,5,4,6,5,5,5,7,5,5,7,5,5,5,6,5,6,5,4,6,5,5,7,5,5,4,5,6,6,3,6,7,8,6,7,5,5,6,5,5,5,5,4,5,5,4,4,6,5,5,5,5,7,5,5,5,5,8,6,6,6,8,7,5,7,5,7,6,6,7,4,6,6,5,7,4,6,3,5,6,5,6,7,4,7,5,8,8,6,7,7,7,5,4,5,5,5,5,4,5,6,5,6,7,5,6,5,6,3,4,6,4,4,4,6,4,5,6,4,5,4,4,3,6,6,4,4,4,4,5,4,5,4,6,5,4,5,4,7,5,6,5,5,7,6,4,5,4,6,4,4,3,5,6,5,5,7,5,7,3,8,6,5,6,8,4,6,7,4,5,3,5,6,5,7,8,4,5,7,6,5,4,3,5,5,7,6,5,8,4,5,6,4,5,4,5,5,5,5,7,4,4,6,7,5,4,5,7,5,5,3,4,7,6,4,6,6,4,6,6,6,5,4,5,3,4,7,4,8,6,7,5,7,5,4,6,6,7,7,6,4,8,7,6,5,7,6,6,7,6,4,5,5,5,4,5,3,4,6,7,5,7,6,6,5,5,6,5,3,6,5,7,4,5,7,6,6,7,5,4,6,7,4,6,7,6,7,7,7,5,4,7,7,6,7,5,4,5,6,5,5,5,5,4,7,6,4,6,4,5,4,4,4,6,4,7,4,7,4,4,5,5,4,3,6,6,4,6,7,3,7,7,5,7,4,3,5,4,5,5,4,5,4,7,4,5,4,4,4,3,6,4,4,4,6,6,4,6,4,4,7,4,5,6,4,4,4,4,5,5,5,4,5,7,5,5,5,4,4,6,3,5,5,5,4,4,3 };


	int stringToWordIndices(std::string str, int16_t *gen_words_indices) {

		std::stringstream X(str);
		std::string word;
		std::vector<std::string> words;
		while (getline(X, word, ' ')) {
			words.push_back(word);
		}

		if (words.size() != NUM_WORDS_MNEMONIC)
		{
			std::cerr << "!!!ERROR PARSE STRING: \"" << str << "\"" << std::endl;
			return -1;
		}

		for (int i = 0; i < NUM_WORDS_MNEMONIC; i++)
		{
			bool found = false;
			if (strcmp(words[i].c_str(), (const char*)"?") == 0)
			{
				gen_words_indices[i] = -1;
				continue;
			}
			for (int ii = 0; ii < 2048; ii++)
			{
				if (strcmp(words[i].c_str(), (const char *)mnemonic_words[ii]) == 0)
				{
					gen_words_indices[i] = ii;
					found = true;
					break;
				}
			}
			if (!found) {
				std::cerr << "!!!ERROR PARSE STRING: \"" << str << "\"" << std::endl;
				std::cerr << "!!!WRONG WORD "<< i <<": \"" << words[i] << "\"" << std::endl;
				return -1;
			}
		}

		return 0;
	}



	void entropyTo12Words(uint64_t entr[2], const int16_t gen_words_indices[12], uint32_t idx, uint8_t* mnemonic_phrase) {
		uint32_t num_worlds_gen = 0;
		int16_t indices[12];
		//generateRandomUint64Buffer(entropy, 2);
		uint64_t entropy[2] = { entr[0] , entr[1] };

		entropy[1] += idx;
		if (idx > entropy[1]) entropy[0]++;

		for (int i = 0; i < 12; i++) indices[i] = -1;
		for (int i = 0; i < 11; i++) if (gen_words_indices[i] != -1) num_worlds_gen++;
		for (int i = 0; i < 11; i++) if (gen_words_indices[i] != -1) indices[i] = gen_words_indices[i];
		for (int i = 11, pos = 11; i >= 0; i--)
		{
			if (indices[i] == -1)
			{
				int16_t ind = 0;
				switch (pos)
				{
				case 0: indices[i] = (entropy[0] >> 53) & 2047; break;
				case 1: indices[i] = (entropy[0] >> 42) & 2047; break;
				case 2: indices[i] = (entropy[0] >> 31) & 2047; break;
				case 3: indices[i] = (entropy[0] >> 20) & 2047; break;
				case 4: indices[i] = (entropy[0] >> 9) & 2047; break;
				case 5: indices[i] = ((entropy[0] & ((1 << 9) - 1)) << 2) | ((entropy[1] >> 62) & 3); break;
				case 6: indices[i] = (entropy[1] >> 51) & 2047; break;
				case 7: indices[i] = (entropy[1] >> 40) & 2047; break;
				case 8: indices[i] = (entropy[1] >> 29) & 2047; break;
				case 9: indices[i] = (entropy[1] >> 18) & 2047; break;
				case 10: indices[i] = (entropy[1] >> 7) & 2047; break;
				case 11: indices[i] = ((entropy[1] & ((1 << 7) - 1)) << 4); 

					break;
				default:
					break;
				}
				pos--;
			}

		}

		entropy[0] = 0; entropy[1] = 0;
		for (int i = 0; i < 12; i++)
		{
			uint64_t temp = indices[i];
			switch (i)
			{
			case 0: entropy[0] |= temp << 53; break;
			case 1: entropy[0] |= temp << 42; break;
			case 2: entropy[0] |= temp << 31; break;
			case 3: entropy[0] |= temp << 20; break;
			case 4: entropy[0] |= temp << 9; break;
			case 5:
				entropy[0] |= temp >> 2;
				entropy[1] |= temp << 62;
				break;
			case 6: entropy[1] |= temp << 51; break;
			case 7: entropy[1] |= temp << 40; break;
			case 8: entropy[1] |= temp << 29; break;
			case 9: entropy[1] |= temp << 18; break;
			case 10: entropy[1] |= temp << 7; break;
			case 11: entropy[1] |= temp >> 4; break;
			default:
				break;
			}
		}

		uint8_t entropy_hash[32];
		uint8_t bytes[16];
		bytes[15] = entropy[1] & 0xFF;
		bytes[14] = (entropy[1] >> 8) & 0xFF;
		bytes[13] = (entropy[1] >> 16) & 0xFF;
		bytes[12] = (entropy[1] >> 24) & 0xFF;
		bytes[11] = (entropy[1] >> 32) & 0xFF;
		bytes[10] = (entropy[1] >> 40) & 0xFF;
		bytes[9] = (entropy[1] >> 48) & 0xFF;
		bytes[8] = (entropy[1] >> 56) & 0xFF;

		bytes[7] = entropy[0] & 0xFF;
		bytes[6] = (entropy[0] >> 8) & 0xFF;
		bytes[5] = (entropy[0] >> 16) & 0xFF;
		bytes[4] = (entropy[0] >> 24) & 0xFF;
		bytes[3] = (entropy[0] >> 32) & 0xFF;
		bytes[2] = (entropy[0] >> 40) & 0xFF;
		bytes[1] = (entropy[0] >> 48) & 0xFF;
		bytes[0] = (entropy[0] >> 56) & 0xFF;
		sha256(entropy_hash, (uint8_t*)bytes, 16);
		uint8_t checksum = (entropy_hash[0] >> 4) & ((1 << 4) - 1);
		indices[11] |= checksum;

		int mnemonic_index = 0;

		for (int i = 0; i < 12; i++) {
			int word_index = indices[i];
			int word_length = mnemonic_word_lengths[word_index];

			for (int j = 0; j < word_length; j++) {
				mnemonic_phrase[mnemonic_index] = mnemonic_words[word_index][j];
				mnemonic_index++;
			}
			mnemonic_phrase[mnemonic_index] = 32;
			mnemonic_index++;
		}

		mnemonic_phrase[mnemonic_index - 1] = 0;	//обязательно, убирает последний пробел

	}

	int pushToMemory(uint8_t* addr_buff, std::vector<std::string>& lines, int max_len) {
		int err = 0;
		for (int x = 0; x < lines.size(); x++) {
			const std::string line = lines[x];
			err = hexStringToBytes(line, &addr_buff[max_len * x], max_len);
			if (err != 0) {
				std::cerr << "\n!!!ERROR HASH160 TO BYTES: " << line << std::endl;
				return err;
			}
		}
		return err;
	}

	int readAllTables(tableStruct* tables, std::string path, std::string prefix, size_t* num_lines)
	{
		int ret = 0;
		std::string num_tables;
		size_t all_lines = 0;
#pragma omp parallel for 
		for (int x = 0; x < 256; x++) {

			std::string table_name = byteToHexString(x);

			std::string file_path = path + "\\" + prefix + table_name + ".csv";

			std::ifstream inFile(file_path);
			int64_t cnt_lines = std::count(std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>(), '\n');
			inFile.close();
			if (cnt_lines != 0) {
				tables[x].table = (uint32_t*)malloc(cnt_lines * 20);
				if (tables[x].table == NULL) {
					printf("Error: malloc failed to allocate buffers.Size %llu. From file %s\n", (unsigned long long int)(cnt_lines * 20), file_path.c_str());
					inFile.close();
					ret = -1;
					break;
				}
				tables[x].size = (uint32_t)_msize((void*)tables[x].table);
				memset((uint8_t*)tables[x].table, 0, cnt_lines * 20);
				inFile.open(file_path, std::ifstream::in);
				if (inFile.is_open())
				{
					std::vector<std::string> lines;
					std::string line;
					while (getline(inFile, line)) {
						lines.push_back(line);
					}

					ret = pushToMemory((uint8_t*)tables[x].table, lines, 20);
					if (ret != 0) {
						std::cerr << "\n!!!ERROR push_to_memory, file: " << file_path << std::endl;
						ret = -1;
						inFile.close();
						break;
					}

					if (cnt_lines != lines.size()) {
						std::cout << "cnt_lines != lines.size(): cnt_lines = " << cnt_lines << " lines.size() = " << lines.size() << std::endl;
					}
					inFile.close();
				}
				else
				{
					std::cerr << "\n!!!ERROR open file: " << file_path << std::endl;
					ret = -1;
					break;
				}
#pragma omp critical 
				{
					all_lines += cnt_lines;
					std::cout << "PROCESSED " << cnt_lines << " ROWS IN FILE " << file_path << "\r";
				}
			}
			else {
#pragma omp critical 
				{
					std::cout << "!!! WORNING !!! COUNT LINES IS 0, FILE " << file_path << std::endl;
				}
			}

		}

		std::cout << "\nALL ADDRESSES IN FILES " << all_lines << std::endl;
		std::cout << "MALLOC ALL RAM MEMORY SIZE (DATABASE): " << std::to_string((float)(all_lines * 20) / (1024.0f * 1024.0f * 1024.0f)) << " GB\n";
		*num_lines += all_lines;
		return ret;
}

	void clearFiles() {
		std::ofstream out;
		out.open(FILE_PATH_RESULT);
		out.close();
	}

	static uint32_t calcCurrPath(uint32_t* path)
	{
		uint32_t curr_path = 0;
		for (int num = 0; num < 10; num++)
		{
			if (path[num] != 0)
			{
				curr_path = num;
				path[num] = 0;
				return curr_path;
			}
		}
		return curr_path;
	}

	void saveResult(char* mnemonic, uint8_t* hash160, size_t num_wallets, size_t num_all_childs, size_t num_childs, uint32_t path_generate[10]) {
		std::ofstream out;
		for (int x = 0; x < NUM_PACKETS_SAVE_IN_FILE; x++) {
			static bool start_string = false;
			out.open(FILE_PATH_RESULT, std::ios::app);
			if (out.is_open())
			{
#pragma omp parallel for 
				for (int i = x * (int)num_wallets / NUM_PACKETS_SAVE_IN_FILE; i < (x * (int)num_wallets / NUM_PACKETS_SAVE_IN_FILE + (int)num_wallets / NUM_PACKETS_SAVE_IN_FILE); i++) {
					std::string addr;
					//std::string hash_str;
					std::stringstream ss;

					ss << (const char*)&mnemonic[SIZE_MNEMONIC_FRAME * i];
					uint32_t curr_path = 66;
					uint32_t path[10];
					for (int num = 0; num < 10; num++) path[num] = path_generate[num];

					for (int ii = 0; ii < num_all_childs; ii++) {
						uint8_t* hash = (uint8_t*)&hash160[(i * num_all_childs + ii) * 20];
						if (ii % num_childs == 0)
							curr_path = calcCurrPath(path);
						if (curr_path == 8 || curr_path == 9)
						{
							char address[42 + 1];
							segwit_addr_encode(address, "bc", 0, (const uint8_t*)hash, 20);
							addr = std::string(address);
							encodeAddressBase32((const uint8_t*)hash, addr);
						}
						else if (curr_path == 6 || curr_path == 7)
						{
							encodeAddressBIP49((const uint8_t*)hash, addr);
						}
						else
						{
							encodeAddressBase58((const uint8_t*)hash, addr);
						}
						ss << "," << addr;
					}
					ss << '\n';
#pragma omp critical (SaveChilds)
					{
						out << ss.str();
					}
				}
			}
			else
			{
				printf("\n!!!ERROR create file %s!!!\n", FILE_PATH_RESULT);
			}
			out.close();
		}
	}
	void addFoundMnemonicInFile(std::string path, std::string mnemonic, std::string address) {
		std::ofstream out;
		out.open(FILE_PATH_FOUND_ADDRESSES, std::ios::app);
		if (out.is_open())
		{
			std::time_t result = std::time(nullptr);
			out << mnemonic << ",address path " << path << "," << address << "," << std::asctime(std::localtime(&result));
		}
		else
		{
			printf("\n!!!ERROR open file %s!!!\n", FILE_PATH_FOUND_ADDRESSES);
		}
		out.close();
	}

	void addInFileTest(int num_bytes, std::string& path, std::string& mnemonic, std::string& hash160, std::string& hash160_in_table, std::string& addr, std::string& addr_in_table) {
		std::ofstream out;
		out.open(FILE_PATH_FOUND_BYTES, std::ios::app);
		if (out.is_open())
		{
			const std::time_t now = std::time(nullptr);
			out << "EQUAL " << num_bytes << "," << mnemonic << ",address path " << path << ":," << addr << "," << "address in table:," << addr_in_table << ",hash160:," << hash160 << ",hash160 in table:," << hash160_in_table << "," << std::asctime(std::localtime(&now));
		}
		else
		{
			printf("\n!!!ERROR open file %s!!!\n", FILE_PATH_FOUND_BYTES);
		}
		out.close();
	}

	std::string getPath(uint32_t path, uint32_t child)
	{
		std::stringstream ss;
		std::string pth = "";
		if (path == 0) ss << "m/0/" << child;
		if (path == 1) ss << "m/1/" << child;
		if (path == 2) ss << "m/0/0/" << child;
		if (path == 3) ss << "m/0/1/" << child;
		if (path == 4) ss << "m/44'/0'/0'/0/" << child;
		if (path == 5) ss << "m/44'/0'/0'/1/" << child;
		if (path == 6) ss << "m/49'/0'/0'/0/" << child;
		if (path == 7) ss << "m/49'/0'/0'/1/" << child;
		if (path == 8) ss << "m/84'/0'/0'/0/" << child;
		if (path == 9) ss << "m/84'/0'/0'/1/" << child;
		return ss.str();
	}




	int checkResult(retStruct* ret) {

		if (ret->f[0].count_found >= MAX_FOUND_ADDRESSES)
		{
			ret->f[0].count_found = MAX_FOUND_ADDRESSES;
			std::cout << "\n!!!WARNING ret->f[0].count_found >= MAX_FOUND_ADDRESSES!!!\n";
			std::cout << "!!!PLEASE INCREASE MAX_FOUND_ADDRESSES" << std::endl;
			std::cout << "!!!WARNING ret->f[0].count_found >= MAX_FOUND_ADDRESSES!!!\n";

		}
		if (ret->f[1].count_found >= MAX_FOUND_ADDRESSES)
		{
			ret->f[1].count_found = MAX_FOUND_ADDRESSES;
			std::cout << "\n!!!WARNING ret->f[1].count_found >= MAX_FOUND_ADDRESSES!!!\n";
			std::cout << "!!!PLEASE INCREASE MAX_FOUND_ADDRESSES" << std::endl;
			std::cout << "!!!WARNING ret->f[1].count_found >= MAX_FOUND_ADDRESSES!!!\n";

		}
		if (ret->f[2].count_found >= MAX_FOUND_ADDRESSES)
		{
			ret->f[2].count_found = MAX_FOUND_ADDRESSES;
			std::cout << "\n!!!WARNING ret->f[2].count_found >= MAX_FOUND_ADDRESSES!!!\n";
			std::cout << "!!!PLEASE INCREASE MAX_FOUND_ADDRESSES" << std::endl;
			std::cout << "!!!WARNING ret->f[2].count_found >= MAX_FOUND_ADDRESSES!!!\n";

		}
		if (ret->f[0].count_found_bytes >= MAX_FOUND_ADDRESSES)
		{
			ret->f[0].count_found_bytes = MAX_FOUND_ADDRESSES;
			std::cout << "\n!!!WARNING ret->f[0].count_found_bytes >= MAX_FOUND_ADDRESSES!!!\n";
			std::cout << "!!!PLEASE INCREASE MAX_FOUND_ADDRESSES" << std::endl;
			std::cout << "!!!WARNING ret->f[0].count_found_bytes >= MAX_FOUND_ADDRESSES!!!\n";

		}
		if (ret->f[1].count_found_bytes >= MAX_FOUND_ADDRESSES)
		{
			ret->f[1].count_found_bytes = MAX_FOUND_ADDRESSES;
			std::cout << "\n!!!WARNING ret->f[1].count_found_bytes >= MAX_FOUND_ADDRESSES!!!\n";
			std::cout << "!!!PLEASE INCREASE MAX_FOUND_ADDRESSES" << std::endl;
			std::cout << "!!!WARNING ret->f[1].count_found_bytes >= MAX_FOUND_ADDRESSES!!!\n";

		}
		if (ret->f[2].count_found_bytes >= MAX_FOUND_ADDRESSES)
		{
			ret->f[2].count_found_bytes = MAX_FOUND_ADDRESSES;
			std::cout << "\n!!!WARNING ret->f[2].count_found_bytes >= MAX_FOUND_ADDRESSES!!!\n";
			std::cout << "!!!PLEASE INCREASE MAX_FOUND_ADDRESSES" << std::endl;
			std::cout << "!!!WARNING ret->f[2].count_found_bytes >= MAX_FOUND_ADDRESSES!!!\n";

		}

		if (ret->f[0].count_found != 0)
		{
			for (uint32_t i = 0; i < ret->f[0].count_found; i++)
			{
				foundInfoStruct* info = &ret->f[0].found_info[i];
				std::string mnemonic_str = (const char*)info->mnemonic;
				std::string addr;
				std::string path = getPath(info->path, info->child);
				tools::encodeAddressBase58((const uint8_t*)info->hash160, addr);
				tools::addFoundMnemonicInFile(path, mnemonic_str, addr);
				std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
				std::cout << "!!!FOUND ADDRESS (" << path << "): " << mnemonic_str << ", " << addr << std::endl;
				std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
			}
		}
		if (ret->f[1].count_found != 0)
		{
			for (uint32_t i = 0; i < ret->f[1].count_found; i++)
			{
				foundInfoStruct* info = &ret->f[1].found_info[i];
				std::string mnemonic_str = (const char*)info->mnemonic;
				std::string addr;
				std::string path = getPath(info->path, info->child);
				tools::encodeAddressBIP49((const uint8_t*)info->hash160, addr);
				tools::addFoundMnemonicInFile(path, mnemonic_str, addr);
				std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
				std::cout << "!!!FOUND ADDRESS (" << path << "): " << mnemonic_str << ", " << addr << std::endl;
				std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
			}
		}
		if (ret->f[2].count_found != 0)
		{
			for (uint32_t i = 0; i < ret->f[2].count_found; i++)
			{
				foundInfoStruct* info = &ret->f[2].found_info[i];
				std::string mnemonic_str = (const char*)info->mnemonic;
				std::string addr;
				std::string path = getPath(info->path, info->child);
				tools::encodeAddressBase32((const uint8_t*)info->hash160, addr);
				tools::addFoundMnemonicInFile(path, mnemonic_str, addr);
				std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
				std::cout << "!!!FOUND ADDRESS (" << path << "): " << mnemonic_str << ", " << addr << std::endl;
				std::cout << "!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n!!!FOUND!!!\n";
			}
		}

		if (ret->f[0].count_found_bytes != 0)
		{
			for (uint32_t i = 0; i < ret->f[0].count_found_bytes; i++)
			{
				foundBytesInfoStruct* info = &ret->f[0].found_bytes_info[i];
				int num_bytes = 0;
				for (int i = 0; i < 20; i++)
				{
					if (*(uint8_t*)((uint8_t*)info->hash160 + i) != *(uint8_t*)((uint8_t*)info->hash160_from_table + i)) break;
					num_bytes++;
				}

				std::string mnemonic_str = (const char*)info->mnemonic;
				std::string hash160 = tools::bytesToHexString((const uint8_t*)info->hash160, 20);
				std::string hash160_in_table = tools::bytesToHexString((const uint8_t*)info->hash160_from_table, 20);
				std::string addr;
				std::string addr_in_table;
				std::string path = getPath(info->path, info->child);
				tools::encodeAddressBase58((const uint8_t*)info->hash160, addr);
				tools::encodeAddressBase58((const uint8_t*)info->hash160_from_table, addr_in_table);
				std::cout << "\n!!!FOUND IN ADDRESS(HASH160) (" << path << ") EQUAL " << num_bytes << " BYTES: " << mnemonic_str << "," << addr << "," << addr_in_table << "," << hash160 << "," << hash160_in_table << " \n";
				tools::addInFileTest(num_bytes, path, mnemonic_str, hash160, hash160_in_table, addr, addr_in_table);
			}
		}
		if (ret->f[1].count_found_bytes != 0)
		{
			for (uint32_t i = 0; i < ret->f[1].count_found_bytes; i++)
			{
				foundBytesInfoStruct* info = &ret->f[1].found_bytes_info[i];
				int num_bytes = 0;
				for (int i = 0; i < 20; i++)
				{
					if (*(uint8_t*)((uint8_t*)info->hash160 + i) != *(uint8_t*)((uint8_t*)info->hash160_from_table + i)) break;
					num_bytes++;
				}

				std::string mnemonic_str = (const char*)info->mnemonic;
				std::string hash160 = tools::bytesToHexString((const uint8_t*)info->hash160, 20);
				std::string hash160_in_table = tools::bytesToHexString((const uint8_t*)info->hash160_from_table, 20);
				std::string addr;
				std::string addr_in_table;
				std::string path = getPath(info->path, info->child);
				tools::encodeAddressBIP49((const uint8_t*)info->hash160, addr);
				tools::encodeAddressBIP49((const uint8_t*)info->hash160_from_table, addr_in_table);
				std::cout << "\n!!!FOUND IN ADDRESS(HASH160) (" << path << ") EQUAL " << num_bytes << " BYTES: " << mnemonic_str << "," << addr << "," << addr_in_table << "," << hash160 << "," << hash160_in_table << " \n";
				tools::addInFileTest(num_bytes, path, mnemonic_str, hash160, hash160_in_table, addr, addr_in_table);
			}
		}
		if (ret->f[2].count_found_bytes != 0)
		{
			for (uint32_t i = 0; i < ret->f[2].count_found_bytes; i++)
			{
				foundBytesInfoStruct* info = &ret->f[2].found_bytes_info[i];
				int num_bytes = 0;
				for (int i = 0; i < 20; i++)
				{
					if (*(uint8_t*)((uint8_t*)info->hash160 + i) != *(uint8_t*)((uint8_t*)info->hash160_from_table + i)) break;
					num_bytes++;
				}

				std::string mnemonic_str = (const char*)info->mnemonic;
				std::string hash160 = tools::bytesToHexString((const uint8_t*)info->hash160, 20);
				std::string hash160_in_table = tools::bytesToHexString((const uint8_t*)info->hash160_from_table, 20);
				std::string addr;
				std::string addr_in_table;
				std::string path = getPath(info->path, info->child);
				tools::encodeAddressBase32((const uint8_t*)info->hash160, addr);
				tools::encodeAddressBase32((const uint8_t*)info->hash160_from_table, addr_in_table);
				std::cout << "\n!!!FOUND IN ADDRESS(HASH160) (" << path << ") EQUAL " << num_bytes << " BYTES: " << mnemonic_str << "," << addr << "," << addr_in_table << "," << hash160 << "," << hash160_in_table << " \n";
				tools::addInFileTest(num_bytes, path, mnemonic_str, hash160, hash160_in_table, addr, addr_in_table);
			}
		}
		return 0;
	}

	}
