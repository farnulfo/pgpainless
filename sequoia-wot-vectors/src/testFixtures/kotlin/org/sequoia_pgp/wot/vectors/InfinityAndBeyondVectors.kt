// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

class InfinityAndBeyondVectors: ArtifactVectors {

    val u1Fpr = Fingerprint("B557862780A97676CC32F4BB1491A9C2BDE6F1DC")
    val u1Uid = "<u1@example.org>"

    val u260Fpr = Fingerprint("B69A678AA242FA4F0BBF12205C0608799B0E3C51")
    val u260Uid = "<u260@example.org>"

    val u254Fpr = Fingerprint("AF097DA4DB5C0E2116EF583B25A6B381B621C082")
    val u254Uid = "<u254@example.org>"

    val fprs = listOf(
            Fingerprint("B557862780A97676CC32F4BB1491A9C2BDE6F1DC"),
            Fingerprint("0618F850B6D0C48DBF406BBFAB3DAED809A35F78"),
            Fingerprint("70B0C5FEFFE6B55F2CEE85455621246D16D6785E"),
            Fingerprint("EC4475DE5BD76EA7DD4798777E9C990C249738B1"),
            Fingerprint("FB00C7044A9DD164243CEC460B48AA8ADD29A129"),
            Fingerprint("7DCB823AB1B33C6D22FC84AC3026DA74AEEB4A6E"),
            Fingerprint("0058DCF7A7C6C4360DE9095DB6F33843D961E818"),
            Fingerprint("D0BF1856B95A62763DE49088CE6FF96D17E0EAF0"),
            Fingerprint("7F945244A20A74E1BA50BE73E917BC24D2D53F79"),
            Fingerprint("12C92685CA2A867B93FD79762B2D56CF0B94304E"),
            Fingerprint("02B1DB86B6869BCF92C0F74312D1A5F22E128F18"),
            Fingerprint("9C8245F2DD06E4A2FE21FB1643A9663DDF7DF168"),
            Fingerprint("CB7C6D3FCBB8DA0B3D7F6EC0DD193A96517579DC"),
            Fingerprint("66D0F95325D4A02A36C14265FD247584CCA3C8BA"),
            Fingerprint("291ABB75D735BC5B625E221B021152DF0CA1F86A"),
            Fingerprint("27DF659AEE573E30D3A65B6E43474D9A4CA64DE3"),
            Fingerprint("591492CAF51C06516278723EAFB9AF2643B89A3A"),
            Fingerprint("20B481FFB7B72F6781BA49806C8E35B5C79A3E41"),
            Fingerprint("270E3D9E87CA0999D422CD22F905BF87E8F60A36"),
            Fingerprint("192124BD42BA6BF54A8820FB94B6B70D818241E3"),
            Fingerprint("07C1D93539328F97517C59D27ABC3071DB73A790"),
            Fingerprint("A915D1BA3F066E989B965ADFA27CC8D161C0F48A"),
            Fingerprint("D968AFB7EAF13E04BB71D96100CC514119C8303E"),
            Fingerprint("A62F988F2896A0286F92F8B8201E7737D11D7039"),
            Fingerprint("9BF8933FCA5306F567F5F5750CE3375AFA9398A1"),
            Fingerprint("5EC7400A739E579B704E618809345EF1045B304A"),
            Fingerprint("2C7B74D1388CE0F2C4002CE41EAD11DBB281472A"),
            Fingerprint("C18D79710A68696E972B0F321E6DE596CD08B4FD"),
            Fingerprint("C1B1150980254353538D9CC5A91187FE2DBD51FF"),
            Fingerprint("4FD94C288F39C4633FBBD120BF1A1C6B6789F983"),
            Fingerprint("DE70A745F098EBCC45B4A3B25D0195EC3C6E0D65"),
            Fingerprint("44350591F20A4069F131156283AABF91FE4AE5EF"),
            Fingerprint("76E9D213C5F67F2DBE410F57DF3F9BB9622AAFC7"),
            Fingerprint("A48F536C34D4A493CD233870C05B675B873B139D"),
            Fingerprint("7C3FEDFAB082D236A9181B8E2B6483A582756C6E"),
            Fingerprint("0FDFAF64606B6C72BF1C940D24F80C95D5B8310E"),
            Fingerprint("6B5A25C2DD40AE58272FB17D15C33EF13B9D7FE8"),
            Fingerprint("3814E465DDDCDB7F352E513D9C34D38E08A4360A"),
            Fingerprint("2BF243991E5B6444861FC662E93888456D33F149"),
            Fingerprint("124760101EF948B0E9EC24D9326FFEBD505BE4D3"),
            Fingerprint("074E083627D1ED618486FB18865EA7123912BE53"),
            Fingerprint("955B6A60E5EA85BADD68B1E08AF3E45D3AB93DE9"),
            Fingerprint("857B9C8DCF9EBD72556237A40E652DDF8101E2D0"),
            Fingerprint("FA11A49DA2E22F686471A4343E6A36C53F7C2155"),
            Fingerprint("90DF0E04097EBFD295E05B9F40BE700A2E8D0995"),
            Fingerprint("90BA919C17ED4252F8F0ED327192D79A112A0CE6"),
            Fingerprint("3762EB478F47FEA848ADA9E1611C433D28D84071"),
            Fingerprint("E960CD893E6CF7F41E752BEF15ED83ECDF49463C"),
            Fingerprint("B1256D987F2789601FC5D8FAF268AB5F6AB44782"),
            Fingerprint("5EE4B68A4828F5C15DD87114DC4A8509993DCFAB"),
            Fingerprint("5C472E1C68A9A587C2AF9F00BC59B13A9918BBC1"),
            Fingerprint("5320428600FCDB9A3AA32DA3E14D0128D7C372EC"),
            Fingerprint("41958AAE8E1EED80B680F4DCD5ABFA33A1DB1C23"),
            Fingerprint("7F4DFF6FC276995C94C2BF92146B7BED38209DB9"),
            Fingerprint("6DE33C3735906B7E69AE593A0CD724AF410A89CE"),
            Fingerprint("70F56B5B0EA57CB9ACDEB08B5333D900488A16B1"),
            Fingerprint("02C9977BFF7BA0295AF671AA31894E2CD88A0F0D"),
            Fingerprint("81FF106638ACE77B0C1039D5E69BCC93690A6B8D"),
            Fingerprint("136368A84C7E56A86515ACC6DCD0744ABE10225D"),
            Fingerprint("2B5E1D94813CED1CD63A3F28FEF343EA790E2333"),
            Fingerprint("680ADF1182D00512D298417C6DBFC9084BFDB79D"),
            Fingerprint("17DFBFB2149AB4A82B1DE5E5AE63FBDCE6874162"),
            Fingerprint("2FD6D0F680B55F9AF128DBCBA4C71E44F433B728"),
            Fingerprint("26551C85DBFDDEA97B7E7A0068DBDE9E792A7A49"),
            Fingerprint("341BB68A3695B3D9EE307D7794317B145CEFCB60"),
            Fingerprint("2E65A5B2F70D16D5D4D0664D360AE9BD58C555C1"),
            Fingerprint("DEE7D3162919AC8AC9592051BFACF193B344DEF1"),
            Fingerprint("2A8CE469DD783B95C92A6F3294A5A609AA679F71"),
            Fingerprint("8A9FE07B40482C5559A6770B57B79188B52BD346"),
            Fingerprint("6993EE3E5C4653A03EACBEC25604E4A55B4F75AB"),
            Fingerprint("66DF2690FEAC606C285AA4D986376ACD1964BE48"),
            Fingerprint("29FD7B1C6B29663CFA64306670E67F3E7F6FBCD4"),
            Fingerprint("2C6E7C99DE5F5922E05D11D235C2E562CC528E76"),
            Fingerprint("88E99AC4D5CB6ACF3CD396D5D6AA9961B4F938AB"),
            Fingerprint("4471A85059215D231D47B1D4A109C3F0B6BDB258"),
            Fingerprint("2C755244C6B83CAA7E48BD234C7FDB8645611B3B"),
            Fingerprint("9C015FEBD3D19A81716E7700052058B47F889611"),
            Fingerprint("9014E514D677C2ED19D93329C1485FE55F1C72D6"),
            Fingerprint("343F2C6F9DB8F9EE4E59F5C0886BAE56FA55CE26"),
            Fingerprint("13C37CE8ED0ACC92CF61808755241D6DA1633FA4"),
            Fingerprint("ED5C07A820DCB2AA6DAFDE9C8562765D88A4BB36"),
            Fingerprint("21655669D7B36A2EB5007B31442FCE197ADCC8D8"),
            Fingerprint("CD220E58B30D2D1CBBC5B921555C92A70B303860"),
            Fingerprint("5FF5C8CBD8D670565B300519887E3ED2F9E0DDA9"),
            Fingerprint("B47FF2EF9DEB08C7FC55532C746F0F2DB723C462"),
            Fingerprint("F8F8F30931EEB93C2FDE9363F9EE328402F33860"),
            Fingerprint("3714D9CB0A8A0B4EE695B21AB052CAE69A2A7689"),
            Fingerprint("FF093E66CCFB8804193115058643E0CB52C5A793"),
            Fingerprint("0A5553209858B36F3EA0EFA463FD6758FF116167"),
            Fingerprint("D9C06C9D100813BEBD35427DF65F7634EB2EAD6A"),
            Fingerprint("05CA2D388297E826B9C3B431A8B15D93895257F9"),
            Fingerprint("BF79DD51D462180014D2AD71D2462BE4CF36F625"),
            Fingerprint("FC0DE4AD683BE64F47E8642F7472D7BB781E5C76"),
            Fingerprint("F1FE09936F39A4E7A907D909CDFA4993BE4124AF"),
            Fingerprint("465CD9AD11B5003A48BB28118DB2CEBD29D4F603"),
            Fingerprint("9DF99BDB7078BE13CE3F66D97F212BF669F995C6"),
            Fingerprint("57071A60EFBBFFA6DDCE7796F14A1B2C681A8A83"),
            Fingerprint("8AB11E4F18DC57F2BA400B8D7B5FD8990C1CCAC5"),
            Fingerprint("286EC5D4E5D1D136E54C996FE2D9E350B7CF3D8A"),
            Fingerprint("AF87AF1183FB3E9370D509CE4E255380D5F3A8D5"),
            Fingerprint("036F0956E3436BB10D030C89241EB37A3E931678"),
            Fingerprint("33C2757572312304682BDD62C46C67D099B92680"),
            Fingerprint("47A458ECE5784E7AF11C2286AA75FA9B8401E257"),
            Fingerprint("43950C8B0B46693E9E48676637A98A31CF4B62AD"),
            Fingerprint("A881411005DCCA6AF01331438783D3432031442F"),
            Fingerprint("AA96AB4A6A98A839676621E66E756674E8DE55F3"),
            Fingerprint("6844B0D8AB1D74A5766311157F652BC182F0875D"),
            Fingerprint("B6F83FFF8B788418D48C11FA084D0F3AC9A2AECD"),
            Fingerprint("99B269CFF458C780108B370C7A3F523A4DD62521"),
            Fingerprint("48ADBA117B6D38703248D7AE72FB58B9E9798B7E"),
            Fingerprint("FBC503FCBE4143C984E88358E700E23D4F573CCF"),
            Fingerprint("E249A634759A417A040615736E200525AAF6F629"),
            Fingerprint("BC782C4357D9E72075AF3DBF2C2FCAB09C09C252"),
            Fingerprint("7B47E68EFB03A0C8346BD80E4A2FA75B6488D6D3"),
            Fingerprint("DC2807A9E1CCD83B797A1EB2829D1F4641E0DB9B"),
            Fingerprint("33C7585C640E74974790F349F64B2668DF09DE8E"),
            Fingerprint("C766141BA6C7998C7EE40DE116FB427F2C57657F"),
            Fingerprint("D0DF7D293426D9451E9EE0FD03A4D8196D10976D"),
            Fingerprint("D56E5DB01CFAAD99697B33163B81D229170F58B4"),
            Fingerprint("97D592FDE6199E3A4F6B437F40B34142AA67397B"),
            Fingerprint("8C19F12A8386D0EF3FC0AFD28D7FE8D90F070EFB"),
            Fingerprint("5B87566BAA2C8EC78C7D44594F21D5ABA36767F2"),
            Fingerprint("53AB6BCCE1111DCD151E66625F52509FC67F4076"),
            Fingerprint("318DA1A8A8E92698EAAC0AB468406FF3D0B6733A"),
            Fingerprint("350068CCCD295D7EB80C6A97060FCBD15175ADB2"),
            Fingerprint("3A7DF039CCCA3B3C9286B01619D8EA302427C910"),
            Fingerprint("3C964F3E9C57330753EE5923B49FC01974400307"),
            Fingerprint("4E9E5E2E1A868706DAADFD5A362C66828E5E4621"),
            Fingerprint("36328DA9EAC85DB46843FA168A4AA6C4B47ADE22"),
            Fingerprint("0AB20633A6D636B80337EFE3403702D89A3CD852"),
            Fingerprint("8CDF07D3CEA5ED1B72ECD8869CA0A447943C1F3B"),
            Fingerprint("E052363BDCA7BB374570774F9EE1EA2E8BF88026"),
            Fingerprint("6603EA823BC641A465D8E5C45EDAD32360EDFC6A"),
            Fingerprint("7D2E0E09E14B5BAB084A268786B0C6357215757B"),
            Fingerprint("44F5446DBE64118D55D007453C6EF4840B47CD82"),
            Fingerprint("419FA3D74A917B54F53AF2157B81A4A67CBA27F0"),
            Fingerprint("36EB37E159817A86D0D4F506A3DDF317DFEDF32F"),
            Fingerprint("9F5918BE6A7898670283859B05280E0DDA09EC95"),
            Fingerprint("24EFDB2253318E11B73B617C6A7C5DC8792A2A55"),
            Fingerprint("4AF832B3208DB3DD126C21E3CAF4AA3126156F8B"),
            Fingerprint("E00EE6E5D079CA81E37F964EAD799F4D59738D54"),
            Fingerprint("5A962B09EF649F4267DFDAE046B2F28E5134573F"),
            Fingerprint("BAB9FB2EC409E68165AEF78D58BB96EB511C41B2"),
            Fingerprint("ADD6E345227F27489E1E8AA7E0CD788437CC47BF"),
            Fingerprint("BCD1FB9A7524E6B2D1ADB920653E81204C30A119"),
            Fingerprint("17DE4392A165DC82CF50E879B5CB17B550CC0DE2"),
            Fingerprint("5E9C128259B95B3C90C651E3E106A3276D83FFD1"),
            Fingerprint("837B524C48C821FB23C4331A764076A4958D02E6"),
            Fingerprint("1DBFA683F2744FCCFCF46D35989519FEB16FB4B1"),
            Fingerprint("16561C850378BDB387F6E620B261465512DF841D"),
            Fingerprint("40903D9038604F9F0325F4F595735AB9651D3899"),
            Fingerprint("542CE462E1A66CEECDE4A15E3B614535DCA71EEF"),
            Fingerprint("91FE56BE25CCB3CF5439DFAAC42E3BADAAFA919A"),
            Fingerprint("0EBD96F41958B13F8F69B5FFD95B370820AE2176"),
            Fingerprint("FE6500EC3768698238FA02AE836FE5675367B4F9"),
            Fingerprint("34E96CA46093CDFC25ACE6A3A2FE701D926F093A"),
            Fingerprint("45046E989B2E1B90A1DAEB5ADB7580D1B78D3BC6"),
            Fingerprint("64A9859344F5073B183BD5C8AA60941E63199D9D"),
            Fingerprint("729EDA4A2A634E776780E1847CA24E9550F7D0A7"),
            Fingerprint("8844DCA493E8F20107CB447191FEA3BD4C01890B"),
            Fingerprint("F965044BE1E7300C7B6716E293C396B4FA94CD92"),
            Fingerprint("BC007EC19B0BC8DDE59847B09EA70EB3222D9E51"),
            Fingerprint("B333A058F7209C46F2D027BB03738EAAC50701ED"),
            Fingerprint("A9A1A3B0F12233D6120809D6F8F0C11D96152693"),
            Fingerprint("2BFE10D7FEE9E5DF5833B6F61B584BAB2FD86575"),
            Fingerprint("E5F3B17D545521F9B5395B10E92020FDB3E8109E"),
            Fingerprint("58035C57B66B0EBFB069F9B7F3C623A5C52A3B92"),
            Fingerprint("003E9C5A9DAB8626FD1694AAC2C43642A20E1496"),
            Fingerprint("E7947E382B12FE628BDA130201EFC9D900B5540C"),
            Fingerprint("17B55B1078D282C73FA2E76287FAB537AEAFE66C"),
            Fingerprint("27CE83D68C669FE4F1B8C938D4A919E6F59E4D0B"),
            Fingerprint("86B1E98692F4CA34122012C1524B4079CF57E850"),
            Fingerprint("5B8A8AC5213064AE84C97DE41ED4BF239D9C10F2"),
            Fingerprint("3FEAB08FC63829C080412CBFC6D3836C6E817789"),
            Fingerprint("231605AEE34762F3BBC8ECF73808EFA9258837F8"),
            Fingerprint("AE2759F4EC850FA6CE98FA4729FD82649411B973"),
            Fingerprint("E7529E3567F59BBCADAAD1246613DBC86DAD45F8"),
            Fingerprint("CF320590351A8C41C9EA0C1F4C6F00F7AEA73AD5"),
            Fingerprint("475A44091578C02A0C5C2D62F106918D87E15476"),
            Fingerprint("5B88BF2E7163D0594CE0E302C2AD0FE43D473EFE"),
            Fingerprint("E4ADA4F5D702AD510C2F7A19316950AD7429C1FA"),
            Fingerprint("6D6B846B8661F1013E7BC8D64C7280F7DF9DA6E6"),
            Fingerprint("49883F6CA68B9F452F2A5F2F04687A6078E00FBF"),
            Fingerprint("3046B5075B9DAF5645F51717D01AB61342900011"),
            Fingerprint("16213F8B540AC28FE0CB3548D84F0D748AC23379"),
            Fingerprint("9C68E98198FF9964FA2366ADCBAD3A465C76396B"),
            Fingerprint("6EC3A10AA0B6B70DC5408CAE74B0BE836FD382D6"),
            Fingerprint("E25E062BE69B48D3B99A96086991D15CA7370F0C"),
            Fingerprint("A01A30A1AB191AF9C148C3704F4582E27D8D7527"),
            Fingerprint("5D33551903E14FAABF75E9ECFB7AE6C2AC9959FB"),
            Fingerprint("B37AE84FB0B4226FB935A3090F7C543F95A21EEF"),
            Fingerprint("65B2CD9E6A6F6A36496B54A285F9BA4B68AA5174"),
            Fingerprint("C0AA5CFC45580335A785DC2B3F9EE769EAAFE70D"),
            Fingerprint("09973DF6334673259B774B840B1496371FDC2BE6"),
            Fingerprint("29AAA5AF7CF941F4307DE966BD9E690D59FE5383"),
            Fingerprint("9BDA50D8A6C78525051AAE07CC26594022C7D4AE"),
            Fingerprint("2B0B6FDB04B9E8FF3A31EBE16A6B0A72A6571C45"),
            Fingerprint("5C2650D8DA9842951614026288805244633C686B"),
            Fingerprint("EEA6502B34AB08FA2F3BDA1E355AC29B6D8B67FA"),
            Fingerprint("61B00DCDC02069F46F20D7F91075929DC6DA674C"),
            Fingerprint("A1F5307F398FA45ECFC68CA92A5FC888D2DD2728"),
            Fingerprint("AB0ADD3BF024EB6C75D9A366ABE69FC6E9F60DA0"),
            Fingerprint("20DFEEF42F418CCEB02DB3E896E40B0413F1B4C5"),
            Fingerprint("59C4E41C31D1E16F11BCF51304E7B81D67AD1FA0"),
            Fingerprint("C0A3A190F8BFB6115A87CF7CBEC9211A2E210C86"),
            Fingerprint("8932D417D3C0C4E3694E90480B92349F276E4EE0"),
            Fingerprint("5BE288B0F7DCD89200D112D009E73AB06030B4EB"),
            Fingerprint("CF472156042D6F2032BC025B68544E0A5844F3A7"),
            Fingerprint("D54401DBBDE32805DAF08C4E1177C10E27F7D235"),
            Fingerprint("56100D18E943687F7CFBC3CB20479A11B7DD5E1D"),
            Fingerprint("9349703A779BD3725C5C822E21DA8172102EC4CD"),
            Fingerprint("5DCAAB77198D13785C340D7B375DD44D815A0481"),
            Fingerprint("5959CAC7EB9C1C7D9ECF10B8C023ED12A0F7F556"),
            Fingerprint("7D4EA25C4F364AF1B61B64164816D289775352A8"),
            Fingerprint("84291C882E059C5100C5C1AD1746298F01E7D682"),
            Fingerprint("F3A95472FDB65D965EC2C4E3D22BD567B60BE41E"),
            Fingerprint("0B9B18FB07F29E89D33AA0A86ED47AC9E7B86518"),
            Fingerprint("2A11B65832E97E65DAA69D690C304130A843F532"),
            Fingerprint("BB1B2F93AE4C4D41B4385AB653A4193345AA17C7"),
            Fingerprint("4B526E27DAA41961F9D89404ED2F25E650D82444"),
            Fingerprint("8DC51F77AEFAE450554792A0C704999EF5D32A6B"),
            Fingerprint("ACD80C31E49FEAF9AA07DBD9FA96E7E857A694DE"),
            Fingerprint("F2A4AE3ABC6DE0475E22B836DB0B8264BE496577"),
            Fingerprint("14AA7B5B7D9088CBBD5FF8CB95F34513BA887EC0"),
            Fingerprint("185A81E45751F6322490BE7987DDCD2A02E38D38"),
            Fingerprint("BFCC758F6B567FF489801B539ED707902064CF71"),
            Fingerprint("6F80DC80D1F4C14810750CAF51FAB910F100F6AB"),
            Fingerprint("D220EB0F833DB97983F221D902D45679E35E555A"),
            Fingerprint("6F757C636ED4E157D6F6570DBC03D6A8FCC6CD68"),
            Fingerprint("C0C4B2D29A88A8F042FB13422605B3290364FF74"),
            Fingerprint("23EBA00A8576434AE4B077F9819A1B623B2E138C"),
            Fingerprint("88C18A2D51339461068DDF72693871FAF6FFC6FF"),
            Fingerprint("CDA5DE7236C247F0D116CC0A1A25910D0CD909C0"),
            Fingerprint("E405060228D49BA43C6ED9A3E25ADFDCC0012F48"),
            Fingerprint("575DB527D78D5A063AB4197891DB2946F8EE3A8C"),
            Fingerprint("D4BBE60FCA2FC7850FF7309102DEF04D111BA114"),
            Fingerprint("97794BE1FD5729470D049D86BE16BB8E38D6D8EB"),
            Fingerprint("4C011F0F9E4C58022DBD2E1FAA549F086FB77001"),
            Fingerprint("950D06C53390F94AF59A15609900DA7A91A638CF"),
            Fingerprint("013B231F139A46312550BBCBC52451FDB72285FC"),
            Fingerprint("A814BA237B27B4605C71A907B8A8D55FC49CB5E6"),
            Fingerprint("A3AE147DBC887FA325852A4DC3FFE143772A8587"),
            Fingerprint("4D88E9B314F4ECAF99E02611C985FD350408C791"),
            Fingerprint("CE9A27BE12483A5F094F85330E51D13DC2830B24"),
            Fingerprint("B6565ADDD563FDD720D05411CD3449BD50892312"),
            Fingerprint("F1EBB0F94C08A777867F403E9FAFBE3A10228952"),
            Fingerprint("94D627E627E15F9B9144457816A736F442FD6A6F"),
            Fingerprint("B3B1CDB5875CD8725B5FC915B1ED7C0FCE7721EE"),
            Fingerprint("9E80CD683AA01265FE25DF265DADCE433039185C"),
            Fingerprint("AFDE99A008E9BC761DFA6367C984AF52546308CF"),
            Fingerprint("364854C36A1EFFDCAC7B80296A8F683B48BC5F33"),
            Fingerprint("77C3730DB611591E71EE4528A15EE7D5EF32333F"),
            Fingerprint("138CC2085B1A06F02DE1946D5FB391D63C886EE6"),
            Fingerprint("AF097DA4DB5C0E2116EF583B25A6B381B621C082"),
            Fingerprint("02DF6CB2758D7695940B6937804CAD30CDAC243C"),
            Fingerprint("7F7C33899D1A34BE0D2B3C1C3B8F983DFABA03B4"),
            Fingerprint("041549DBA90F2C4EB9E22505B4515224EB745A2C"),
            Fingerprint("B73206C4F70E0735E9288128BAC3400233738122"),
            Fingerprint("FCDF4C1D67ACFA8B42F6A77C408A9CB7367171C2"),
            Fingerprint("B69A678AA242FA4F0BBF12205C0608799B0E3C51"),
    )

    /**
     * A few minutes after the network has been generated.
     */
    val t0 = parseReferenceTime("2022-01-28 15:18:00 UTC")

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/infinity-and-beyond.pgp"
    }
}