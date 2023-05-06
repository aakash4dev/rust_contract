use near_bigint::U256;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{log, near_bindgen};
// use near_sys::alt_bn128_pairing_check;
pub use pairing::{pairing_prod_4, G1Point, G2Point};
use near_sdk::sys::{alt_bn128_pairing_check};
mod pairing;

#[near_bindgen]
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Verifier {
    pub alfa1: G1Point,
    pub beta2: G2Point,
    pub gamma2: G2Point,
    pub delta2: G2Point,
    pub ic: Vec<G1Point>,
    pub snark_scalar_field: U256,
}

#[near_bindgen]
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Proof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

impl Default for Verifier {
    fn default() -> Self {
        Self {
            alfa1: G1Point {
                x: U256::from_dec_str("19588571812112913444313220207184812430901027328814934314041336494389579727490").unwrap(),
                y: U256::from_dec_str("20876620758613883198678971399947228020349152495363712824452439555681722703844").unwrap(),
            },
            beta2: G2Point {
                x: [U256::from_dec_str("1147493305972264361212333694047172493748629835776584342561122245368117789090").unwrap(), U256::from_dec_str("15546110242127298774725801171866202053855864729583087780269711803018153583170").unwrap()],
                y: [U256::from_dec_str("15670534484052726488703126009147413779716090823943941203768509391720636478498").unwrap(), U256::from_dec_str("13018026423551894160093592214570497989649376948777150787778860795428582397888").unwrap()],
            },
            gamma2: G2Point {
                x: [U256::from_dec_str("11559732032986387107991004021392285783925812861821192530917403151452391805634").unwrap(), U256::from_dec_str("10857046999023057135944570762232829481370756359578518086990519993285655852781").unwrap()],
                y: [U256::from_dec_str("4082367875863433681332203403145435568316851327593401208105741076214120093531").unwrap(), U256::from_dec_str("8495653923123431417604973247489272438418190587263600148770280649306958101930").unwrap()],
            },
            delta2: G2Point {
                x: [U256::from_dec_str("14502308529068562960482656727141207655910101847204149533190076802856916253544").unwrap(), U256::from_dec_str("19564662523331646217337334776200297798706313172317028914539039054142262951344").unwrap()],
                y: [U256::from_dec_str("19322636740713750153562137600202408323948637463899977496356907007307802584587").unwrap(), U256::from_dec_str("1859245150258807714578483262611774465897891037769776678764335798540115311482").unwrap()],
            },
            ic: vec![
                G1Point {
                    x: U256::from_dec_str("4644302044163333633193668138034373579414780561355523521723820139850096127065").unwrap(),
                    y: U256::from_dec_str("132535718064324173610843892132061711715429019920237103560054147710479734773").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("14554669171440115333844386954501235788482823021448975290988850856000453137445").unwrap(),
                    y: U256::from_dec_str("15002479857639310915298102325332865643131837488227837028042726097524180093326").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("15370991053439701469942838257923255079256254046451912781889016072148452485672").unwrap(),
                    y: U256::from_dec_str("4176615531706953255626978772143037677602892540361958067692355765102082357337").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("20539785643982557478026712029584933401021503864766142111582958110590338700112").unwrap(),
                    y: U256::from_dec_str("19430995276710238415684904893655769876439459251929521375243707806372117590784").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("11725685233460118159820907864104231439876089430389909065313281206385414507032").unwrap(),
                    y: U256::from_dec_str("16056476202664483182329846818982632736942122561947765687868922709091562559291").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("21695831149408299634922629842817243220085005611590226615671048250162614655184").unwrap(),
                    y: U256::from_dec_str("18648672120444705458764496847005342365239328095925993823328308608649954726254").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("2271110670428055567263028240342058037482103864212879985810985403598999273706").unwrap(),
                    y: U256::from_dec_str("12997413602519288510713962115597272724990022604286736132673962433801246000049").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("18343737722410686590178463933407560801826990291159516138870655023837236454386").unwrap(),
                    y: U256::from_dec_str("5060651789061501225716561747808622063433612419601620777445629673430574614825").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("11518482939170289486754265733952727297782112382492490810094334870020430476840").unwrap(),
                    y: U256::from_dec_str("11048428986216303472170333660651625309899038238690847000913234477377756198354").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("10767153191540959885762408168351920205686132146086701867538812095784207407809").unwrap(),
                    y: U256::from_dec_str("480036892345808583214857114547714816060283901653328559653954993510898823909").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("336114676963785838441014648216337192305629155434336421248213369993624926457").unwrap(),
                    y: U256::from_dec_str("216079891848391936525210061899404833866118143577240207687006500026219727089").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("5939643244813210302133397993610876567210952368856885383167455483088364830979").unwrap(),
                    y: U256::from_dec_str("5505317684091419746092577478581993752834987705141079168705726218790237730928").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("5805951290615465405718293708580383126620201949982812989225375155995451738777").unwrap(),
                    y: U256::from_dec_str("8879647661617174987046207571048295892423326283958683499039540288674172540770").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("5946254426584511361439725352027427168161861235008733552901212652599306121563").unwrap(),
                    y: U256::from_dec_str("9694751706916623990571562094159679421936257088365418036843450226070685620992").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("21558597461063231518312188386625299310859850517010321926880286706724343215404").unwrap(),
                    y: U256::from_dec_str("2622528610726282086389269575855668158862410787889296736214992639313799452084").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("14016077367638741466906863513819094500952467638916525284608320156527897015872").unwrap(),
                    y: U256::from_dec_str("2800367344608083542014367806924511209810351685365595004988390829131180253375").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("7083531183518299055528755501641715584641206369801444800294447992588260177205").unwrap(),
                    y: U256::from_dec_str("17560794771640656181857507672170822811323764420402375988818933624397975190779").unwrap(),
                },
                G1Point {
                    x: U256::from_dec_str("18303669516366849880986497067732709432571836721574521624438124669702263289311").unwrap(),
                    y: U256::from_dec_str("5447274593936750119188702475306374856446500173093805160656987650356707635449").unwrap(),
                },
            ],
            snark_scalar_field: U256::from_dec_str("21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap(),
        }
    }
}

#[near_bindgen]
impl Verifier {

    pub fn verify(&self, input: Vec<U256>, proof: Proof) -> bool {
        assert_eq!(input.len() + 1, self.ic.len(), "verifier-bas-input");
        log!("input.len() + 1: {} , self.ic.len() {}",input.len() + 1, self.ic.len());

        let mut vk_x = G1Point {
            x: U256::zero(),
            y: U256::zero(),
        };
        vk_x = G1Point::addition(&vk_x, &self.ic[0]);
        log!("{:?}",vk_x);
        // panic!("{:x?}", input_bytes);
        for i in 0..input.len() {
            assert!(
                input[i] < self.snark_scalar_field,
                "verifier-gte-snark-scalar-field"
            );

            vk_x = G1Point::addition(&vk_x, &self.ic[i + 1].scalar_mul(input[i]));
        }

        // * pairing_prod_4() starts here:
        let temp_value = &proof.a.negate();
        let p1: Vec<&G1Point> = vec![&temp_value, &self.alfa1, &vk_x, &proof.c];
        let p2: Vec<&G2Point> = vec![&proof.b, &self.beta2, &self.gamma2, &self.delta2];

        // * pairing(p1,p2) ::: pairing(p1: Vec<&G1Point>, p2: Vec<&G2Point>) -> bool 
        assert!(p1.len() == p2.len(), "pairing-lengths-failed");
		log!("p1.len {}, p2.len {}",p1.len(),p2.len());
        let mut bytes = Vec::with_capacity(p1.len() * 6 * 32);
        let mut buf = [0u8; 64 + 128];
        for i in 0..p1.len() {
            buf[0..32].copy_from_slice(&p1[i].x.to_le_bytes());
            buf[32..64].copy_from_slice(&p1[i].y.to_le_bytes());
            buf[64..96].copy_from_slice(&p2[i].x[0].to_le_bytes());
            buf[96..128].copy_from_slice(&p2[i].x[1].to_le_bytes());
            buf[128..160].copy_from_slice(&p2[i].y[0].to_le_bytes());
            buf[160..192].copy_from_slice(&p2[i].y[1].to_le_bytes());
            bytes.extend_from_slice(&buf);
        }

        log!("bytes:- {:?}",bytes);

        let value_ptr = bytes.as_ptr() as u64;
        let value_len = bytes.len() as u64;

        log!("value_ptr:- {:?}", value_ptr);
        log!("value_len:- {:?}", value_len);

        // * working till here
        // ! not working: unsafe { alt_bn128_pairing_check(value_len, value_ptr) != 0 }

        let somevalue = unsafe { alt_bn128_pairing_check(value_ptr, value_len) != 0 };
        log!("{:?}", somevalue);
        // some value should be true or false.

        // alt_bn128_pairing_check
        return true;
    }
}
