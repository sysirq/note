int __thiscall sub_856600(_DWORD *this, int a2)
{
  _DWORD *v2; // esi
  int v3; // ebx
  int v4; // eax
  int v5; // ST0C_4
  const struct LuaPlus::LuaStackObject *v6; // eax
  const struct LuaPlus::LuaStackObject *v7; // eax
  const struct LuaPlus::LuaStackObject *v8; // eax
  const struct LuaPlus::LuaStackObject *v9; // eax
  const struct LuaPlus::LuaStackObject *v10; // eax
  const struct LuaPlus::LuaStackObject *v11; // eax
  const struct LuaPlus::LuaStackObject *v12; // eax
  const struct LuaPlus::LuaStackObject *v13; // eax
  void *v14; // eax
  void *v15; // eax
  int v16; // eax
  void *v17; // eax
  void *v18; // eax
  int v19; // eax
  const struct LuaPlus::LuaStackObject *v20; // eax
  void *v21; // eax
  void *v22; // eax
  int v23; // eax
  const struct LuaPlus::LuaStackObject *v24; // eax
  void *v25; // eax
  void *v26; // eax
  int v27; // eax
  const struct LuaPlus::LuaStackObject *v28; // eax
  void *v29; // eax
  void *v30; // eax
  int v31; // eax
  const struct LuaPlus::LuaStackObject *v32; // eax
  void *v33; // eax
  void *v34; // eax
  int v35; // eax
  const struct LuaPlus::LuaStackObject *v36; // eax
  void *v37; // eax
  void *v38; // eax
  int v39; // eax
  const struct LuaPlus::LuaStackObject *v40; // eax
  void *v41; // eax
  void *v42; // eax
  int v43; // eax
  const struct LuaPlus::LuaStackObject *v44; // eax
  void *v45; // eax
  void *v46; // eax
  int v47; // eax
  const struct LuaPlus::LuaStackObject *v48; // eax
  void *v49; // eax
  void *v50; // eax
  int v51; // eax
  const struct LuaPlus::LuaStackObject *v52; // eax
  void *v53; // eax
  void *v54; // eax
  int v55; // eax
  const struct LuaPlus::LuaStackObject *v56; // eax
  void *v57; // eax
  void *v58; // eax
  int v59; // eax
  const struct LuaPlus::LuaStackObject *v60; // eax
  void *v61; // eax
  void *v62; // eax
  int v63; // eax
  const struct LuaPlus::LuaStackObject *v64; // eax
  void *v65; // eax
  void *v66; // eax
  int v67; // eax
  const struct LuaPlus::LuaStackObject *v68; // eax
  void *v69; // eax
  void *v70; // eax
  int v71; // eax
  const struct LuaPlus::LuaStackObject *v72; // eax
  void *v73; // eax
  void *v74; // eax
  int v75; // eax
  const struct LuaPlus::LuaStackObject *v76; // eax
  const struct LuaPlus::LuaStackObject *v77; // eax
  const struct LuaPlus::LuaStackObject *v78; // eax
  const struct LuaPlus::LuaStackObject *v79; // eax
  const struct LuaPlus::LuaStackObject *v80; // eax
  const struct LuaPlus::LuaStackObject *v81; // eax
  void *v82; // eax
  int v83; // eax
  int v84; // eax
  const struct LuaPlus::LuaStackObject *v85; // eax
  const struct LuaPlus::LuaStackObject *v86; // eax
  const struct LuaPlus::LuaStackObject *v87; // eax
  const struct LuaPlus::LuaStackObject *v88; // eax
  void *v89; // eax
  void *v90; // eax
  int v91; // eax
  const struct LuaPlus::LuaStackObject *v92; // eax
  void *v93; // eax
  int v94; // eax
  int v95; // eax
  const struct LuaPlus::LuaStackObject *v96; // eax
  void *v97; // eax
  void *v98; // eax
  int v99; // eax
  const struct LuaPlus::LuaStackObject *v100; // eax
  void *v101; // eax
  void *v102; // eax
  int v103; // eax
  const struct LuaPlus::LuaStackObject *v104; // eax
  void *v105; // eax
  void *v106; // eax
  int v107; // eax
  const struct LuaPlus::LuaStackObject *v108; // eax
  void *v109; // eax
  void *v110; // eax
  int v111; // eax
  const struct LuaPlus::LuaStackObject *v112; // eax
  _DWORD *v113; // eax
  void *v114; // eax
  void *v115; // eax
  int v116; // eax
  const struct LuaPlus::LuaStackObject *v117; // eax
  void *v118; // eax
  void *v119; // eax
  int v120; // eax
  const struct LuaPlus::LuaStackObject *v121; // eax
  void *v122; // eax
  void *v123; // eax
  int v124; // eax
  const struct LuaPlus::LuaStackObject *v125; // eax
  void *v126; // eax
  void *v127; // eax
  int v128; // eax
  const struct LuaPlus::LuaStackObject *v129; // eax
  void *v130; // eax
  void *v131; // eax
  int v132; // eax
  const struct LuaPlus::LuaStackObject *v133; // eax
  void *v134; // eax
  void *v135; // eax
  int v136; // eax
  const struct LuaPlus::LuaStackObject *v137; // eax
  void *v138; // eax
  void *v139; // eax
  int v140; // eax
  const struct LuaPlus::LuaStackObject *v141; // eax
  void *v142; // eax
  void *v143; // eax
  int v144; // eax
  const struct LuaPlus::LuaStackObject *v145; // eax
  void *v146; // eax
  void *v147; // eax
  int v148; // eax
  const struct LuaPlus::LuaStackObject *v149; // eax
  void *v150; // eax
  void *v151; // eax
  int v152; // eax
  const struct LuaPlus::LuaStackObject *v153; // eax
  void *v154; // eax
  void *v155; // eax
  int v156; // eax
  const struct LuaPlus::LuaStackObject *v157; // eax
  void *v158; // eax
  void *v159; // eax
  int v160; // eax
  const struct LuaPlus::LuaStackObject *v161; // eax
  void *v162; // eax
  void *v163; // eax
  int v164; // eax
  const struct LuaPlus::LuaStackObject *v165; // eax
  void *v166; // eax
  void *v167; // eax
  int v168; // eax
  const struct LuaPlus::LuaStackObject *v169; // eax
  void *v170; // eax
  void *v171; // eax
  int v172; // eax
  const struct LuaPlus::LuaStackObject *v173; // eax
  void *v174; // eax
  void *v175; // eax
  int v176; // eax
  const struct LuaPlus::LuaStackObject *v177; // eax
  void *v178; // eax
  void *v179; // eax
  int v180; // eax
  const struct LuaPlus::LuaStackObject *v181; // eax
  void *v182; // eax
  void *v183; // eax
  int v184; // eax
  const struct LuaPlus::LuaStackObject *v185; // eax
  void *v186; // eax
  void *v187; // eax
  int v188; // eax
  const struct LuaPlus::LuaStackObject *v189; // eax
  void *v190; // eax
  int v191; // eax
  int v192; // eax
  const struct LuaPlus::LuaStackObject *v193; // eax
  void *v194; // eax
  int v195; // eax
  int v196; // eax
  const struct LuaPlus::LuaStackObject *v197; // eax
  void *v198; // eax
  void *v199; // eax
  int v200; // eax
  const struct LuaPlus::LuaStackObject *v201; // eax
  void *v202; // eax
  int v203; // eax
  int v204; // eax
  const struct LuaPlus::LuaStackObject *v205; // eax
  void *v206; // eax
  int v207; // eax
  int v208; // eax
  const struct LuaPlus::LuaStackObject *v209; // eax
  void *v210; // eax
  void *v211; // eax
  int v212; // eax
  const struct LuaPlus::LuaStackObject *v213; // eax
  void *v214; // eax
  void *v215; // eax
  int v216; // eax
  const struct LuaPlus::LuaStackObject *v217; // eax
  void *v218; // eax
  void *v219; // eax
  int v220; // eax
  const struct LuaPlus::LuaStackObject *v221; // eax
  void *v222; // eax
  void *v223; // eax
  int v224; // eax
  const struct LuaPlus::LuaStackObject *v225; // eax
  void *v226; // eax
  int v227; // eax
  int v228; // eax
  const struct LuaPlus::LuaStackObject *v229; // eax
  void *v230; // eax
  int v231; // eax
  int v232; // eax
  const struct LuaPlus::LuaStackObject *v233; // eax
  void *v234; // eax
  int v235; // eax
  int v236; // eax
  const struct LuaPlus::LuaStackObject *v237; // eax
  void *v238; // eax
  void *v239; // eax
  int v240; // eax
  const struct LuaPlus::LuaStackObject *v241; // eax
  void *v242; // eax
  int v243; // eax
  int v244; // eax
  const struct LuaPlus::LuaStackObject *v245; // eax
  void *v246; // eax
  void *v247; // eax
  int v248; // eax
  const struct LuaPlus::LuaStackObject *v249; // eax
  void *v250; // eax
  int v251; // eax
  int v252; // eax
  const struct LuaPlus::LuaStackObject *v253; // eax
  void *v254; // eax
  void *v255; // eax
  int v256; // eax
  const struct LuaPlus::LuaStackObject *v257; // eax
  void *v258; // eax
  int v259; // eax
  int v260; // eax
  const struct LuaPlus::LuaStackObject *v261; // eax
  void *v262; // eax
  void *v263; // eax
  int v264; // eax
  const struct LuaPlus::LuaStackObject *v265; // eax
  void *v266; // eax
  void *v267; // eax
  int v268; // eax
  const struct LuaPlus::LuaStackObject *v269; // eax
  void *v270; // eax
  void *v271; // eax
  int v272; // eax
  const struct LuaPlus::LuaStackObject *v273; // eax
  void *v274; // eax
  int v275; // eax
  int v276; // eax
  const struct LuaPlus::LuaStackObject *v277; // eax
  void *v278; // eax
  void *v279; // eax
  int v280; // eax
  const struct LuaPlus::LuaStackObject *v281; // eax
  void *v282; // eax
  int v283; // eax
  int v284; // eax
  const struct LuaPlus::LuaStackObject *v285; // eax
  void *v286; // eax
  int v287; // eax
  int v288; // eax
  const struct LuaPlus::LuaStackObject *v289; // eax
  void *v290; // eax
  void *v291; // eax
  int v292; // eax
  const struct LuaPlus::LuaStackObject *v293; // eax
  void *v294; // eax
  void *v295; // eax
  int v296; // eax
  const struct LuaPlus::LuaStackObject *v297; // eax
  void *v298; // eax
  void *v299; // eax
  int v300; // eax
  const struct LuaPlus::LuaStackObject *v301; // eax
  void *v302; // eax
  int v303; // eax
  int v304; // eax
  const struct LuaPlus::LuaStackObject *v305; // eax
  void *v306; // eax
  void *v307; // eax
  int v308; // eax
  const struct LuaPlus::LuaStackObject *v309; // eax
  void *v310; // eax
  void *v311; // eax
  int v312; // eax
  const struct LuaPlus::LuaStackObject *v313; // eax
  void *v314; // eax
  void *v315; // eax
  int v316; // eax
  const struct LuaPlus::LuaStackObject *v317; // eax
  void *v318; // eax
  void *v319; // eax
  int v320; // eax
  const struct LuaPlus::LuaStackObject *v321; // eax
  void *v322; // eax
  int v323; // eax
  int v324; // eax
  const struct LuaPlus::LuaStackObject *v325; // eax
  void *v326; // eax
  void *v327; // eax
  int v328; // eax
  const struct LuaPlus::LuaStackObject *v329; // eax
  void *v330; // eax
  int v331; // eax
  int v332; // eax
  const struct LuaPlus::LuaStackObject *v333; // eax
  void *v334; // eax
  int v335; // eax
  int v336; // eax
  const struct LuaPlus::LuaStackObject *v337; // eax
  void *v338; // eax
  int v339; // eax
  int v340; // eax
  const struct LuaPlus::LuaStackObject *v341; // eax
  void *v342; // eax
  int v343; // eax
  int v344; // eax
  const struct LuaPlus::LuaStackObject *v345; // eax
  void *v346; // eax
  int v347; // eax
  int v348; // eax
  const struct LuaPlus::LuaStackObject *v349; // eax
  void *v350; // eax
  void *v351; // eax
  int v352; // eax
  const struct LuaPlus::LuaStackObject *v353; // eax
  void *v354; // eax
  void *v355; // eax
  int v356; // eax
  const struct LuaPlus::LuaStackObject *v357; // eax
  void *v358; // eax
  void *v359; // eax
  int v360; // eax
  const struct LuaPlus::LuaStackObject *v361; // eax
  char v363; // [esp+10h] [ebp-156Ch]
  char v364; // [esp+18h] [ebp-1564h]
  char v365; // [esp+20h] [ebp-155Ch]
  char v366; // [esp+28h] [ebp-1554h]
  char v367; // [esp+30h] [ebp-154Ch]
  char v368; // [esp+38h] [ebp-1544h]
  char v369; // [esp+40h] [ebp-153Ch]
  char v370; // [esp+48h] [ebp-1534h]
  char v371; // [esp+50h] [ebp-152Ch]
  char v372; // [esp+58h] [ebp-1524h]
  char v373; // [esp+60h] [ebp-151Ch]
  char v374; // [esp+68h] [ebp-1514h]
  char v375; // [esp+70h] [ebp-150Ch]
  char v376; // [esp+78h] [ebp-1504h]
  char v377; // [esp+80h] [ebp-14FCh]
  char v378; // [esp+88h] [ebp-14F4h]
  char v379; // [esp+90h] [ebp-14ECh]
  char v380; // [esp+98h] [ebp-14E4h]
  char v381; // [esp+A0h] [ebp-14DCh]
  char v382; // [esp+A8h] [ebp-14D4h]
  char v383; // [esp+B0h] [ebp-14CCh]
  char v384; // [esp+B8h] [ebp-14C4h]
  char v385; // [esp+C0h] [ebp-14BCh]
  char v386; // [esp+C8h] [ebp-14B4h]
  char v387; // [esp+D0h] [ebp-14ACh]
  char v388; // [esp+D8h] [ebp-14A4h]
  char v389; // [esp+E0h] [ebp-149Ch]
  char v390; // [esp+E8h] [ebp-1494h]
  char v391; // [esp+F0h] [ebp-148Ch]
  char v392; // [esp+F8h] [ebp-1484h]
  char v393; // [esp+100h] [ebp-147Ch]
  char v394; // [esp+108h] [ebp-1474h]
  char v395; // [esp+110h] [ebp-146Ch]
  char v396; // [esp+118h] [ebp-1464h]
  char v397; // [esp+120h] [ebp-145Ch]
  char v398; // [esp+128h] [ebp-1454h]
  char v399; // [esp+130h] [ebp-144Ch]
  char v400; // [esp+138h] [ebp-1444h]
  char v401; // [esp+140h] [ebp-143Ch]
  char v402; // [esp+148h] [ebp-1434h]
  char v403; // [esp+150h] [ebp-142Ch]
  char v404; // [esp+158h] [ebp-1424h]
  char v405; // [esp+160h] [ebp-141Ch]
  char v406; // [esp+168h] [ebp-1414h]
  char v407; // [esp+170h] [ebp-140Ch]
  char v408; // [esp+178h] [ebp-1404h]
  char v409; // [esp+180h] [ebp-13FCh]
  char v410; // [esp+188h] [ebp-13F4h]
  char v411; // [esp+190h] [ebp-13ECh]
  char v412; // [esp+198h] [ebp-13E4h]
  char v413; // [esp+1A0h] [ebp-13DCh]
  char v414; // [esp+1A8h] [ebp-13D4h]
  char v415; // [esp+1B0h] [ebp-13CCh]
  char v416; // [esp+1B8h] [ebp-13C4h]
  char v417; // [esp+1C0h] [ebp-13BCh]
  char v418; // [esp+1C8h] [ebp-13B4h]
  char v419; // [esp+1D0h] [ebp-13ACh]
  char v420; // [esp+1D8h] [ebp-13A4h]
  char v421; // [esp+1E0h] [ebp-139Ch]
  char v422; // [esp+1E8h] [ebp-1394h]
  char v423; // [esp+1F0h] [ebp-138Ch]
  char v424; // [esp+1F8h] [ebp-1384h]
  char v425; // [esp+200h] [ebp-137Ch]
  char v426; // [esp+208h] [ebp-1374h]
  char v427; // [esp+210h] [ebp-136Ch]
  char v428; // [esp+218h] [ebp-1364h]
  char v429; // [esp+220h] [ebp-135Ch]
  char v430; // [esp+228h] [ebp-1354h]
  char v431; // [esp+230h] [ebp-134Ch]
  char v432; // [esp+238h] [ebp-1344h]
  char v433; // [esp+240h] [ebp-133Ch]
  char v434; // [esp+248h] [ebp-1334h]
  char v435; // [esp+250h] [ebp-132Ch]
  char v436; // [esp+258h] [ebp-1324h]
  char v437; // [esp+260h] [ebp-131Ch]
  char v438; // [esp+268h] [ebp-1314h]
  char v439; // [esp+270h] [ebp-130Ch]
  char v440; // [esp+278h] [ebp-1304h]
  char v441; // [esp+280h] [ebp-12FCh]
  char v442; // [esp+288h] [ebp-12F4h]
  char v443; // [esp+290h] [ebp-12ECh]
  char v444; // [esp+298h] [ebp-12E4h]
  char v445; // [esp+2A0h] [ebp-12DCh]
  char v446; // [esp+2A8h] [ebp-12D4h]
  char v447; // [esp+2B0h] [ebp-12CCh]
  char v448; // [esp+2B8h] [ebp-12C4h]
  char v449; // [esp+2C0h] [ebp-12BCh]
  char v450; // [esp+2C8h] [ebp-12B4h]
  char v451; // [esp+2D0h] [ebp-12ACh]
  char v452; // [esp+2D8h] [ebp-12A4h]
  char v453; // [esp+2E0h] [ebp-129Ch]
  char v454; // [esp+2E8h] [ebp-1294h]
  char v455; // [esp+2F0h] [ebp-128Ch]
  char v456; // [esp+2F8h] [ebp-1284h]
  char v457; // [esp+300h] [ebp-127Ch]
  char v458; // [esp+308h] [ebp-1274h]
  char v459; // [esp+310h] [ebp-126Ch]
  char v460; // [esp+318h] [ebp-1264h]
  char v461; // [esp+320h] [ebp-125Ch]
  char v462; // [esp+328h] [ebp-1254h]
  int v463; // [esp+330h] [ebp-124Ch]
  void *v464; // [esp+334h] [ebp-1248h]
  void *v465; // [esp+338h] [ebp-1244h]
  char v466; // [esp+33Ch] [ebp-1240h]
  char v467; // [esp+354h] [ebp-1228h]
  char v468; // [esp+36Ch] [ebp-1210h]
  char v469; // [esp+384h] [ebp-11F8h]
  char v470; // [esp+39Ch] [ebp-11E0h]
  char v471; // [esp+3B4h] [ebp-11C8h]
  char v472; // [esp+3CCh] [ebp-11B0h]
  char v473; // [esp+3E4h] [ebp-1198h]
  char v474; // [esp+3FCh] [ebp-1180h]
  char v475; // [esp+414h] [ebp-1168h]
  char v476; // [esp+42Ch] [ebp-1150h]
  char v477; // [esp+444h] [ebp-1138h]
  char v478; // [esp+45Ch] [ebp-1120h]
  char v479; // [esp+474h] [ebp-1108h]
  char v480; // [esp+48Ch] [ebp-10F0h]
  char v481; // [esp+4A4h] [ebp-10D8h]
  char v482; // [esp+4BCh] [ebp-10C0h]
  char v483; // [esp+4D4h] [ebp-10A8h]
  char v484; // [esp+4ECh] [ebp-1090h]
  char v485; // [esp+504h] [ebp-1078h]
  char v486; // [esp+51Ch] [ebp-1060h]
  char v487; // [esp+534h] [ebp-1048h]
  char v488; // [esp+54Ch] [ebp-1030h]
  char v489; // [esp+564h] [ebp-1018h]
  char v490; // [esp+57Ch] [ebp-1000h]
  char v491; // [esp+594h] [ebp-FE8h]
  char v492; // [esp+5ACh] [ebp-FD0h]
  char v493; // [esp+5C4h] [ebp-FB8h]
  char v494; // [esp+5DCh] [ebp-FA0h]
  char v495; // [esp+5F4h] [ebp-F88h]
  char v496; // [esp+60Ch] [ebp-F70h]
  char v497; // [esp+624h] [ebp-F58h]
  char v498; // [esp+63Ch] [ebp-F40h]
  char v499; // [esp+654h] [ebp-F28h]
  char v500; // [esp+66Ch] [ebp-F10h]
  char v501; // [esp+684h] [ebp-EF8h]
  char v502; // [esp+69Ch] [ebp-EE0h]
  char v503; // [esp+6B4h] [ebp-EC8h]
  char v504; // [esp+6CCh] [ebp-EB0h]
  char v505; // [esp+6E4h] [ebp-E98h]
  char v506; // [esp+6FCh] [ebp-E80h]
  char v507; // [esp+714h] [ebp-E68h]
  char v508; // [esp+72Ch] [ebp-E50h]
  char v509; // [esp+744h] [ebp-E38h]
  char v510; // [esp+75Ch] [ebp-E20h]
  char v511; // [esp+774h] [ebp-E08h]
  char v512; // [esp+78Ch] [ebp-DF0h]
  char v513; // [esp+7A4h] [ebp-DD8h]
  char v514; // [esp+7BCh] [ebp-DC0h]
  char v515; // [esp+7D4h] [ebp-DA8h]
  char v516; // [esp+7ECh] [ebp-D90h]
  char v517; // [esp+804h] [ebp-D78h]
  char v518; // [esp+81Ch] [ebp-D60h]
  char v519; // [esp+834h] [ebp-D48h]
  char v520; // [esp+84Ch] [ebp-D30h]
  char v521; // [esp+864h] [ebp-D18h]
  char v522; // [esp+87Ch] [ebp-D00h]
  char v523; // [esp+894h] [ebp-CE8h]
  char v524; // [esp+8ACh] [ebp-CD0h]
  char v525; // [esp+8C4h] [ebp-CB8h]
  char v526; // [esp+8DCh] [ebp-CA0h]
  char v527; // [esp+8F4h] [ebp-C88h]
  char v528; // [esp+90Ch] [ebp-C70h]
  char v529; // [esp+924h] [ebp-C58h]
  char v530; // [esp+93Ch] [ebp-C40h]
  char v531; // [esp+954h] [ebp-C28h]
  char v532; // [esp+96Ch] [ebp-C10h]
  char v533; // [esp+984h] [ebp-BF8h]
  char v534; // [esp+99Ch] [ebp-BE0h]
  char v535; // [esp+9B4h] [ebp-BC8h]
  char v536; // [esp+9CCh] [ebp-BB0h]
  char v537; // [esp+9E4h] [ebp-B98h]
  char v538; // [esp+9FCh] [ebp-B80h]
  char v539; // [esp+A14h] [ebp-B68h]
  char v540; // [esp+A2Ch] [ebp-B50h]
  char v541; // [esp+A44h] [ebp-B38h]
  char v542; // [esp+A5Ch] [ebp-B20h]
  char v543; // [esp+A74h] [ebp-B08h]
  char v544; // [esp+A8Ch] [ebp-AF0h]
  char v545; // [esp+AA4h] [ebp-AD8h]
  char v546; // [esp+ABCh] [ebp-AC0h]
  char v547; // [esp+AD4h] [ebp-AA8h]
  char v548; // [esp+AECh] [ebp-A90h]
  char v549; // [esp+B04h] [ebp-A78h]
  char v550; // [esp+B1Ch] [ebp-A60h]
  char v551; // [esp+B34h] [ebp-A48h]
  char v552; // [esp+B4Ch] [ebp-A30h]
  char v553; // [esp+B64h] [ebp-A18h]
  char v554; // [esp+B7Ch] [ebp-A00h]
  char v555; // [esp+B94h] [ebp-9E8h]
  char v556; // [esp+BACh] [ebp-9D0h]
  char v557; // [esp+BC4h] [ebp-9B8h]
  char v558; // [esp+BDCh] [ebp-9A0h]
  char v559; // [esp+BF4h] [ebp-988h]
  char v560; // [esp+C0Ch] [ebp-970h]
  char v561; // [esp+C24h] [ebp-958h]
  char v562; // [esp+C3Ch] [ebp-940h]
  char v563; // [esp+C54h] [ebp-928h]
  char v564; // [esp+C6Ch] [ebp-910h]
  char v565; // [esp+C84h] [ebp-8F8h]
  char v566; // [esp+C9Ch] [ebp-8E0h]
  char v567; // [esp+CB4h] [ebp-8C8h]
  char v568; // [esp+CCCh] [ebp-8B0h]
  char v569; // [esp+CE4h] [ebp-898h]
  char v570; // [esp+CFCh] [ebp-880h]
  char v571; // [esp+D14h] [ebp-868h]
  char v572; // [esp+D2Ch] [ebp-850h]
  char v573; // [esp+D44h] [ebp-838h]
  char v574; // [esp+D5Ch] [ebp-820h]
  char v575; // [esp+D74h] [ebp-808h]
  char v576; // [esp+D8Ch] [ebp-7F0h]
  char v577; // [esp+DA4h] [ebp-7D8h]
  char v578; // [esp+DBCh] [ebp-7C0h]
  char v579; // [esp+DD4h] [ebp-7A8h]
  char v580; // [esp+DECh] [ebp-790h]
  char v581; // [esp+E04h] [ebp-778h]
  char v582; // [esp+E1Ch] [ebp-760h]
  char v583; // [esp+E34h] [ebp-748h]
  char v584; // [esp+E4Ch] [ebp-730h]
  char v585; // [esp+E64h] [ebp-718h]
  char v586; // [esp+E7Ch] [ebp-700h]
  char v587; // [esp+E94h] [ebp-6E8h]
  char v588; // [esp+EACh] [ebp-6D0h]
  char v589; // [esp+EC4h] [ebp-6B8h]
  char v590; // [esp+EDCh] [ebp-6A0h]
  char v591; // [esp+EF4h] [ebp-688h]
  char v592; // [esp+F0Ch] [ebp-670h]
  char v593; // [esp+F24h] [ebp-658h]
  char v594; // [esp+F3Ch] [ebp-640h]
  char v595; // [esp+F54h] [ebp-628h]
  char v596; // [esp+F6Ch] [ebp-610h]
  char v597; // [esp+F84h] [ebp-5F8h]
  char v598; // [esp+F9Ch] [ebp-5E0h]
  char v599; // [esp+FB4h] [ebp-5C8h]
  char v600; // [esp+FCCh] [ebp-5B0h]
  char v601; // [esp+FE4h] [ebp-598h]
  char v602; // [esp+FFCh] [ebp-580h]
  char v603; // [esp+1014h] [ebp-568h]
  char v604; // [esp+102Ch] [ebp-550h]
  char v605; // [esp+1044h] [ebp-538h]
  char v606; // [esp+105Ch] [ebp-520h]
  char v607; // [esp+1074h] [ebp-508h]
  char v608; // [esp+108Ch] [ebp-4F0h]
  char v609; // [esp+10A4h] [ebp-4D8h]
  char v610; // [esp+10BCh] [ebp-4C0h]
  char v611; // [esp+10D4h] [ebp-4A8h]
  char v612; // [esp+10ECh] [ebp-490h]
  char v613; // [esp+1104h] [ebp-478h]
  char v614; // [esp+111Ch] [ebp-460h]
  char v615; // [esp+1134h] [ebp-448h]
  char v616; // [esp+114Ch] [ebp-430h]
  char v617; // [esp+1164h] [ebp-418h]
  char v618; // [esp+117Ch] [ebp-400h]
  char v619; // [esp+1194h] [ebp-3E8h]
  char v620; // [esp+11ACh] [ebp-3D0h]
  char v621; // [esp+11C4h] [ebp-3B8h]
  char v622; // [esp+11DCh] [ebp-3A0h]
  char v623; // [esp+11F4h] [ebp-388h]
  char v624; // [esp+120Ch] [ebp-370h]
  char v625; // [esp+1224h] [ebp-358h]
  char v626; // [esp+123Ch] [ebp-340h]
  char v627; // [esp+1254h] [ebp-328h]
  char v628; // [esp+126Ch] [ebp-310h]
  char v629; // [esp+1284h] [ebp-2F8h]
  char v630; // [esp+129Ch] [ebp-2E0h]
  char v631; // [esp+12B4h] [ebp-2C8h]
  char v632; // [esp+12CCh] [ebp-2B0h]
  char v633; // [esp+12E4h] [ebp-298h]
  char v634; // [esp+12FCh] [ebp-280h]
  char v635; // [esp+1314h] [ebp-268h]
  char v636; // [esp+132Ch] [ebp-250h]
  char v637; // [esp+1344h] [ebp-238h]
  char v638; // [esp+135Ch] [ebp-220h]
  char v639; // [esp+1374h] [ebp-208h]
  char v640; // [esp+138Ch] [ebp-1F0h]
  char v641; // [esp+13A4h] [ebp-1D8h]
  char v642; // [esp+13BCh] [ebp-1C0h]
  char v643; // [esp+13D4h] [ebp-1A8h]
  char v644; // [esp+13ECh] [ebp-190h]
  char v645; // [esp+1404h] [ebp-178h]
  char v646; // [esp+141Ch] [ebp-160h]
  char v647; // [esp+1434h] [ebp-148h]
  char v648; // [esp+144Ch] [ebp-130h]
  char v649; // [esp+1464h] [ebp-118h]
  char v650; // [esp+147Ch] [ebp-100h]
  char v651; // [esp+1494h] [ebp-E8h]
  char v652; // [esp+14ACh] [ebp-D0h]
  char v653; // [esp+14C4h] [ebp-B8h]
  char v654; // [esp+14DCh] [ebp-A0h]
  char v655; // [esp+14F4h] [ebp-88h]
  char v656; // [esp+150Ch] [ebp-70h]
  char v657; // [esp+1524h] [ebp-58h]
  char v658; // [esp+153Ch] [ebp-40h]
  char v659; // [esp+1554h] [ebp-28h]
  int v660; // [esp+1578h] [ebp-4h]

  v2 = this;
  sub_876A30();
  v2[7] = (*(int (__stdcall **)(const char *, int *))(*(_DWORD *)dword_D3D214 + 88))("EnableLuaCrash", &v463);
  if ( !v463 )
    v2[7] = 1;
  v3 = ((int (*)(void))sub_856580)();
  v4 = sub_856580(&v659);
  LuaPlus::LuaState::GetGlobals(v4, v5);
  v660 = 0;
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Division",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_568720,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_Multiply",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5687D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CancelQuitWait",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57F090,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnterQuitWait",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57ED70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CheckSOSecond",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57EFA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskRet2SelServer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_579F80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ServerLogin",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_568910,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "QuitApplication",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_568950,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ReturnServerLogin",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_568B50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetActivePointCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_568B70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnumActivePoint",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_568BC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnumActivePointRatio",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_568D90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetActivePoint",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_568E70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetLastSkill_UI",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569020,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleSkillBook",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569060,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSkillBook",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5691D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenZhenfaFream",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569200,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "TogglePetPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569240,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "XiuLianPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5696F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenMijiPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569840,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenJingMaiPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569720,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenRidePage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569A80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenShenDingPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569AB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenJunXianPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569BD0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenOtherJunXianPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569C40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSelfNobilityPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569CA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetPlayerQuickEnterHide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569F30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetPlayerQuickEnterHideNewCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569D10,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetPlayerQuickEnterHideNew",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569D70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenOtherNobilityPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56A0A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OtherInfoPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5699E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenLifePage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56A100,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenCommonSkillPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56A130,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleContainer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56A150,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleMission",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56A170,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetActionNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B060,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnumAction",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B6D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenXiuChang",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B840,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenXiuChangRoom",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B880,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetXiuChangParams",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56BA30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsHaveEquipZiZhi",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56BC50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsIdentifyEquipZiZhi",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56BCE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnumMilitaryRankSkillAction",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56BEB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsPetEquipHaveZiZhi",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56BD80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsIdentifyPetEquipZiZhi",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56BE10,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMilitaryRankAttrib",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56C020,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMilitaryRankExpPhase",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56C1A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMilitaryRankExpTop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56C290,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMilitaryRankName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56C380,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMilitaryRankDesc",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56C480,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMilitaryRankCondition",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56C580,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMaxMilitaryRankLevel",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56C680,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowRankName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56C730,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RankName_IsShow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56C790,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowContexMenu",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56C7E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowDropMailList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56CA60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "MailListClicked",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56CD30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowCommonMenu",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56CD90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "QuestFrameOptionClicked",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D190,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ComposeItem_Begin",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D2D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ComposeItem_Cancel",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D570,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "QuestFrameAcceptClicked",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D600,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "QuestFrameRefuseClicked",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D610,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "QuestFrameMissionContinue",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DEC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "QuestFrameMissionComplete",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DED0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "QuestFrameMissionAbnegate",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DF30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PushDebugMessage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56A2A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_TDU_Log",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56A1C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PushDbgMsgEx",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56A390,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Get_XParam_GetIntCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573650,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Get_XParam_INT",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5736B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Get_XParam_UINT",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573750,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Get_XParam_STR",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5737F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Get_XParam_INT_Count",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573880,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Get_XParam_STR_Count",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5738E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Clear_XSCRIPT",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573940,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Send_XSCRIPT",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573960,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Set_XSCRIPT_Parameter",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573A40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Set_XSCRIPT_Function_Name",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573AC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Set_XSCRIPT_ScriptID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573B40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Set_XSCRIPT_ParamCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573B90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsWindowShow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D240,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SplitGUID64",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573BF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CloseAllWindow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575300,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SkillsStudyFrame_study",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B550,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendAskStudyXinfa",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B5B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetUplevelXinfaSpendMoney",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B0E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetUplevelXinfaSpendExp",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B2F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetXinfaLevel",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B400,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleMissionOutLine",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56A190,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ScriptGlobal_Format",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56A840,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LoadTrack",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D620,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenQianKunDai",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D850,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenHuiGui",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D8B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenZhanLing",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D910,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenMonthlySign",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DB00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenStrongRoadDiaoWen",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DB60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenShouKaiKaUI",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DE20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenFuJiangTianLong",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DE40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenZhaoHui",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D970,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SetZhaoHuiButtonState",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DA40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetZhaoHuiButtonState",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DA50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSuperSaveUp",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56D9E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "KillTimer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_886B70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetTimer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_886B50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ClearAllTimer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_886B90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "UpdateDoubleExpData",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_568890,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleWuhunPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569270,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_OpenPetMasterPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58E100,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_OpenOtherPetMasterPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58E250,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_OpenFiveElementsPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5692A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_OpenOtherFiveElementsPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5692D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_OpenFiveElementsTip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569300,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_CloseFiveElementsTip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569610,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenQianKunDaiSP",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DC20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenMonthlySignSP",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DC80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenStrongRoadDiaoWenSP",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DCE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenJieRiJiangLiSP",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DD40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenNewSalaryTask",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DBC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenNewSalaryTaskSP",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DDB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenHuiGuiSP",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DE10,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleComposeWnd",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DF80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnumMethod",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DFA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMethodNumber",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56DFF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendChatMessage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E3B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendGMCommand",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573600,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AxTrace",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E030,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleLargeMap",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E510,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleSceneMap",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E590,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "UpdateMinimap",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E810,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenMinimap",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E730,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShowShopCredit",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EFF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenBooth",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F030,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CloseBooth",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F050,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RepairAll",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F070,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RepairOne",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F220,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Archer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F240,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PrepearAddFriend",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F6F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PrepearExchange",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F850,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PrepearAsunder",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F970,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PrepearSale",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F710,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PrepearBuyMult",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F730,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GotoNormal",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F830,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PrepearShopDresser",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F810,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CheckBuyMult",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F750,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleYuanbaoShop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E820,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenYBShopReference",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E840,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleXuanShop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E880,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_OpenRlOpPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E8A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenRecentBuyYuanbaoShop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E9B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ClearRecentBuyYuanbaoShop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E9D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenRecentBuyYuanbaoShop_Bind",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E9F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ClearRecentBuyYuanbaoShop_Bind",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EA10,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetOperationType",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F500,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShopType",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F540,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenRecentBuyLiJinShop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EF00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ClearRecentBuyLiJinShop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EF20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CalcItemSpace",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EAB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CalcItemSpace_BindProperty",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EB30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CalcItemSpaceType",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EBF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetBagSpace",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EE70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenRecentBuyGiftTokenShop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EA30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ClearRecentBuyGiftTokenShop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EA50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenRecentBuyVipShop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EBB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ClearRecentBuyVipShop",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EBD0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMultiUpperLimit",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EA70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Booth_EnterGiveGift",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EEE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCurrentSceneName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56F260,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSceneNameByResID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586830,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetSceneIDByResID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5869A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSceneSize",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E0B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSceneSizeByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E120,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSceneMapByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E1E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSceneID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E270,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSceneServerID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E2E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ResetCamera",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56EF40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenCharacter",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56FAE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenEquip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56FB40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskLevelUp",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573340,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskLevelUpAfterValidate",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5733A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskLevelUpAfterSec",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5733C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskNewLevelUpCode",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573410,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AnswerLevelUpCode",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5734C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskEvaluateAndLevelup",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5735E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenTitleList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56FA90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CloseTitleList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56FAC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenEquip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56FBC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SuggestChangeEuip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586240,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetAction_ItemID_FromMyPacket",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5863F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenShopFitting",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56FC20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CloseShopFitting",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5726A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsItemExist",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_572540,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsItemExist_NoLimit",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5728A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetTargetPlayerGUID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5725D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RestoreShopFitting",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56FC50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ChangeShopFittingRaceID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5707F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ClearCurFittingItemByType",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_570850,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CurFittingItemByTypeStatus",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5708A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMountID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_571E00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "FakeObj_SetCamera",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5722B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "NewFakeObj_SetCamera",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5722B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "FakeObj_RestoreCamera",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5724B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "FakeObj_ChangeCameraDistance",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_571FF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "FakeObj_GetCamera",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5721E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetDefaultMouse",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_572510,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "MouseCmd_ShopFittingSet",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5726E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsIdleLogic",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_572710,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetNotifyTip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_572760,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsMoveLogic",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5727C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "StopMove",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_572810,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ReWearFromFittingItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_570920,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsInStall",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_571D50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskEquipDetial",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5746E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetItemBindStatus",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57F140,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OnOpenCampaign",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5886E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCurCampaignID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_588750,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetCampaignShow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_588790,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCampaignIsShow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5887E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowSystemInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57F1F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowSystemInfoEx",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57F310,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnumCampaign",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57FC70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnumNoWholedayCampaign",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_587E00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetIndexInTodayCampaignList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5884E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetIndexInTodayCampaignListWholeday",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5885E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCampaignCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57FAF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenTodayCampaignList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5805E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ResetNewCurrentCampainList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580630,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetNewCampaignCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5895C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnumNewCampaign",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_588820,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "InitNewCampainList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5895B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetOpenCampaignType",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5896A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCampaingTypeByCamID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_589700,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCampaignCountByClass",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580640,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCampaignInfoByClass",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580770,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsInLimitCampaingTableByCamID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_589980,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SendMemoCountMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580A60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetMemoCountNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580AE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_OpenMemo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580BC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ResetMemoList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580BE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetMemoCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57F460,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_EnumMemo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57F580,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenShimingrenzhengDlg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580BF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenFangChenMiInfoDlg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580C30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendSafeSignMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580C80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSecKillList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58EB40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendSecKillDataMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58EB60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSecKillData",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58EC70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSecKillFuBenCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58ED50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSecKillInfoByIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58EDA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSecKillPage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58EF90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SecKillEnumItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58F1F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSecKillBossIconByIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58F340,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SecKillItemListEmpty",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58F560,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SecKillRemoveItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58F5D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SecKillGiveUpItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58F670,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnumSecKillTable",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58F760,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SecKillGetIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58F960,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SecKillGetFuBenId",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58F9E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskShideShopData",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FBA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ToggleRecruitDungeonUI",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FC30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ToggleRecruitDungeonMiniUI",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FC90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ToggleSwearDungeonUI",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FCF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ToggleSwearDungeonMiniUI",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FD50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_OpenVipZZEquipTransfer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FF70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_OpenFiveElementsTypeSwitch",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FFA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_CloseFiveElementsWashConfirm",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590020,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_FiveElementsWashSwitchConfirm",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590050,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_FiveElementsAutoWashConfirm",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5900B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_FiveElementsNotSwitchConfirm",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5900E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_FiveElementsAutoWashStart",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590140,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenBugFeedBack",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E930,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Show_Team_Func_Menu",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573CC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetCurSelMember",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_574150,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Update_PartyFrame_Menu",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_574190,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Show_Team_Member_Pet_Menu",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5741B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowTeamInfoDlg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5740A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "FlashTeamButton",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_574100,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "FlashPacketButton",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_579230,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "NotifyPacketStatus",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_579250,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CountDown10Sec",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5792C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenFreshmanIntro",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_579D80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "DiscardItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5747F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "DiscardItemCancelLocked",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_574E80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LockAfterConfirm",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_574FD0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CancelLockAfterConfirm",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5750F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CancleMifaLock",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575100,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskDelComboBook",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575110,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskLevelupComboBook",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5751D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetXiuweiNextNeed",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575290,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetGlobalInteger",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5744C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetGlobalInteger",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5745E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenTargetMenu",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575310,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowChangePVPMode",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575350,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenWordrefence",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575390,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenAutoSearch",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5754E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSafeScore",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575500,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSafePattern",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575520,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenMobilePhone",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575540,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSafeTime",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575560,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenAccountProtection",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575580,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSecondPassword",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5755A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSafeCheck",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5755C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenLockUnlock",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5755E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskSafeScore",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576830,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenMessageBox",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575600,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskMibaoStatus",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5768B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskMobiePhoneStatus",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576940,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenPlayerList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575620,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsInTServer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5777E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_IsInZBSScene",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577850,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsInYaoTaServer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5778E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsInCangWuServer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577960,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowAcceptChangePVPMode",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575640,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMousePos",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575AC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowSystemTipInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575B30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenChangeMinorPasswordDlg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575B90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenUnLockeMinorPasswordDlg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575BC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CheckPhoneMibaoAndMinorPassword",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575BE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CheckPhoneMibaoAndMinorPasswordForCYJ",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575C40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsHardWareProtectSetup",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575CF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsAppWareProtectSetup",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575D40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CheckHardWareMibao",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575E60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CheckPlayerAccountSafety",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575EC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AppWareFastCheck",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575D90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AppWareGetLeftCheckTime",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575E20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_CheckChangYouJiaPlus",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575F20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetApprovedPhoneFlag",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575CA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsMinorPwdUnlocked",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576020,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetAuthorizedSafeFlag",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576080,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetAuthorizedSafeFlag",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5760E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CheckMinorPassword",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5761B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenSetMinorPasswordDlg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576210,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendSetMinorPassword",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576240,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendModifyMinorPassword",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576330,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "UnLockMinorPassword",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576490,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ForceUnLockMinorPassword",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576580,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ModifyMinorPassword",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5766E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskPhoneMibaoStatus",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576820,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCurrentTime",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B490,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCurMousePos",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56B4E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenWindow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576A10,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CloseWindow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576A60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleWindow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576AF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenOneParamWindow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576B40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowNotice",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576ED0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetMenuBarPageNumber",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5789D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "DuelByGuid_OKClicked",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576D60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "DuelByName_OKClicked",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576BE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "DuelAccept",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_575890,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "TurnMenuBar",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5779E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PutSkillToMainmenuBar",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577B00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PutActionToMainmenuBar",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577CF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ActiveComboSkillToMainmenuBar",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577EB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "NewFreshManPutSkillToMainmenuBar",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577DC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskServerTimeAgain",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5775E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "InviteRide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577F40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AcceptInviteRide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577FE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ApplyRide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5780C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AcceptApplyRide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578180,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "DisbandRide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578230,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CancelRide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578340,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "InviteTeamRide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578500,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CanInvite",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578600,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendScrollInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578670,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaCancelRide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5786B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetExpAssign",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573BE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EquipItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578790,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "UseMiFaAfterSure",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578860,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "WRCollectVisiableContex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_576FC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "WRGetVisiableContex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5771F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "WRGetVisiableContexCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577320,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "WRGetVisiableContexID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577380,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "WRCollectVisiableContexEx",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577130,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "WRGetContexType",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577060,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "WRGetTitle",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577420,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "WRAskTime",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577550,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "WRBOSSTblCollectVisiableContex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_577670,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "WRBOSSTblGetContexInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5776D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnterReconnect",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578A20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CancelReconnect",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578C50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCurClientSize",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578C60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetDictionaryString",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578DA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PKStateImgClicked",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578EC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMissionOutlineNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578EF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMissionOutlineInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_578F70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CollectMissionOutline",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_579200,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowPacket",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_579210,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "YDNewUserCard",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5792E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "NewUserCard",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5794A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PassportCard",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_579A50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CheckCardType",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_579980,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetRideStatic",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_579DF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMasterName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_579FE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMasterGuildName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57A820,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMasterLevel",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57B060,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMasterIsOnline",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57B810,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetMasterGroupAndIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57BFD0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetTudiGroupAndIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57C350,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "BankAcquireListWithPW",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57C730,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenDlg4ProtectTime",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57C830,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SetProtectTime",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57C9A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SendSetProtectTimeMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57CB00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetSoftKeyAim",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57CB10,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendSetProtectTimeMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57CB50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AutoRunToTarget",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57CC20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AutoRunToTargetEx",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57CD00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AutoRuntoTargetExWithName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57CE20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFnIsAcrossSceneMove",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57D030,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetJieRiHuoDongInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57D100,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetZhanLingPrizeInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57D460,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetAutoRunTargetNPCName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57D960,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "MsgBall",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57E160,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskDetailByGuid",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57E7F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SafeBox",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_57D9D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CacheMainTarget",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580CA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PushEvent",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580CB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CloseFangDaohao",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580FC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetPlayerFromList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_580FE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetMainTargetFromList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_581810,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "UpdatePlayerList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5817A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "UpdatePlayerListCustom",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_581800,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CallScriptString",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_581C80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "MessageBoxCommon",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_581A70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CloseMessageBoxCommon",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_581C60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CloseInputYuanbao",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_581F20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RequestFindFriendList",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_581F40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RequestFindFriendDetailInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_582080,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RequestAddOrEditFindFriendInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5821E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "FindFriendQuery",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5823A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RequestDeleteFindFriendInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_582530,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RequestVoteFindFriendInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_582670,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RequestSearchFindFriendInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5828F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RequestOpenZhengyouMessage",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_582A70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RequestServerNoteLog",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_582BC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ConvertStringToURLCoding",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_582D10,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CalciDiaoYanVCode",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583020,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetGameVersion",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5831D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSelfGUID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583200,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenMinorPassword",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5832A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenFangdao",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5832E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsMinorPwdSetup",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583300,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleAutoSearch",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5835B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AutoSearchTargetFlashPos",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583620,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "StartAutoMove",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5837D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenDianhuaMibao",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583810,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleMsgHistory",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583830,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaConfirmChangeSex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583850,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaConfirmChangeSexChild",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583A10,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PopComfirm_Alpha0",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583BD0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PopComfirm_Alpha1",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583CC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SelectTargetOfTarget",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583350,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShoujiTargetTujian",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583420,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskQinmiToTudi",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5834A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ParserString",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_583DB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "DelProtectGoodsOps",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5840A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsInHell",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_569180,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AdjustUIPos",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5843F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Open_Reconnect_Msg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584440,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Delay_Connect",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584480,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetWeblink",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_572930,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendAskIMDressChestPacket",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584490,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressChestGetSelIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584530,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressGetDressInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584570,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMSaveToPayBox",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5848A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMClearFromPayBox",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585360,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressPayMoney",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584A60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressPayMoneyToOther",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584C70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressCleanUpPayBox",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584F30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressCleanUpPayBoxOnly",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584F60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressLoadPayBox",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584F80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressSendChangeDress",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_584FC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMySelfRaceId",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5850B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShopFittingRaceID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585100,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressSavePayBoxToBackup",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585150,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressLoadPayBoxFromBackup",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585170,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressGetIndexByDressPoint",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585190,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressIsDressOn",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585240,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressGetPayBoxPrice",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5852D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMDressGetUsefulLife",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5853D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "XushizuoqiGetUsefulLife",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585490,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMGetItemTableIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585520,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IMSendDeleteMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585690,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ChangeChatWindowMode",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585750,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PackUpIMDressChest",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5857D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CleanUpPreIMDressMailBox",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585980,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PreIMDressMailBoxGetCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5859A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PreIMDressMailBoxGetSelectedCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5859E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PreIMDressMailBoxGetSize",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585A20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PreIMDressMailBoxSetSelect",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585A60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PreIMDressMailBoxGetSelect",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585AF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PreIMDressMailBoxGetGiverName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585B70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskPreIMDressMail",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585C10,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskPreIMDressALLMail",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585DB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskPreIMDressMailInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_585F40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskJHShituInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586050,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SCItemSet_SetItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586080,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SCItemSet_GetItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586140,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SCItemSet_Count",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5861C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SCItemSet_Clear",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586200,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SCItemSet_Update",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5862C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SCItemSet_PushItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586370,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ChangeSuggestEuip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586530,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "NewFreshManRideTuto",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586630,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetSceneNameByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5866D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ToggleCreateGroup",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_572AA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Chongzhi",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_572BF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "YuanbaoExange",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_572CB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFindRoleByAcc",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573050,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenCustomerService",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573090,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenJNHZB",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573140,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenDFSZB",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_573240,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsUnbindChongLouEquip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586A70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenHuoYueHaoLi",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E950,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenWeekHuoyuehaoli",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E970,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenZBSPromoteMap",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_56E990,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowOffApplyTeam",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586B00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ShowOffRequestTeam",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586C20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RefreshShowOffMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586D60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShowOffGuidByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586E30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShowOffNameByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586F40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShowOffMenpaiByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_586FF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShowOffLevelByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_587350,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShowOffSexByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_587410,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShowOffGuildNameByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5874D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShowOffTitleByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_587580,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShowOffMoodByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_587640,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetShowOffImageNameByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5876F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetTime2Minite",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_587B40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SendCampaignCountMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_587BC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCampaignCountNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_587C40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCampaignTotalNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_587D30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ChangeMain",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58A2A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PlayerCameraTrack",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58A3A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "KvkShowOffApplyTeam",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5911D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "KvkShowOffRequestTeam",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591300,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RefreshKvkShowOffMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591460,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffGuidByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590170,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffNameByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590280,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffMenpaiByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590670,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffLevelByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5909D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffSexByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590A90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffGuildNameByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590B50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffTitleByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590CF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffMoodByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590DB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffImageNameByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5910C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffServerName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590C00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffZMName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590E60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffScoreHH",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_590F40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetKvkShowOffZoneWorldID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591000,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetClanState",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58A2B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetMenpaiByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_587800,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenFreshManGuide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58A410,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CloseFreshManGuide",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58A670,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetFreshManGuideOwner",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58A6A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "NotifyPopUITip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58A6E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "EnumMainMenuBarAction",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58A7D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetWindowPos",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58A920,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenWebClient",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58A9F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CheckEnablePYQ",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58AAE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetEnablePYQ",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58AB10,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenFreshManGuideNew",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58AB60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CreateRealChonglouModle",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58AE20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SnsGameBuyItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_589B40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ConvenientBuyItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_589C70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetTime2Day",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58AFD0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsFlyChange",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B070,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsInFatigueState",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B0C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ConvenientBulkBuyItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_589F80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ANSI2TM",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B130,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskYoulongkaInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B210,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetClientVersionType",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B310,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CreateChar_RenameNote_Ret",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B350,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsAcrossSceneMoveto",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B290,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetChampionCupMatch",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B370,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetChampionCupTeam",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B620,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetChampionCupTeamMember",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B700,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetChampionCupGroupTeamScore",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B880,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetChampionCupMatchForGuess",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58BCD0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetChampionCupMatchOver",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58B9A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetChampionCupMatchForGuessNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58BC90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetChampionCupMatchOverNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58BC50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetChampionCupMatchBetInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58BF80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetMatchGuessScore",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C030,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_IsChampionGupMatchDataValid",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C070,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "lua_OpenChampionGupTeamInfoWindow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C0B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "lua_CloseChampionGupTeamInfoWindow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C110,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetUpdateInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C130,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetUpdateInfoNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C2E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ToggleFengyunlu",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C610,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OpenFlash",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C360,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetGemChangRule",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C370,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetGemPrice",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C490,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetGemType",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C550,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C630,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluTitle",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C6B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C850,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluOverText",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C930,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluMissionListTitle",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C9F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluIcon",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58C790,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluMissionIDNeed",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58CAB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluMissionTextDone",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58CBC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluMissionTextHave",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58CDE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluMissionTextNoHave",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D010,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SetFengyunluInt",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D230,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFengyunluInt",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D290,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_DroppedStatistics",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D2D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SetCurSelectedSceneID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D350,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SendMazeiRequest",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D3B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SendMineralRequest",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D460,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ChangeToAccountInputDlgForLoginOverTime",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D570,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ChangeToAccountInputDlgForReCheckMibao",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D5D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RunXunYou",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D7C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "AskServerNew_FirstOne",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58E310,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_CloseHuiTianDanMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58F710,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetChangeClientType",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D510,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ForbidRunCmdLine",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D550,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "RunCmdLine",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D560,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetNobilityName",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58E390,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetXinShouHeroesRoadInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58E6F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetMaiDianNumByDay",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58EA00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SortHaoXia",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58E540,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetHaoXiaIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58E590,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetHaoXiaIndexChange",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58E640,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "ConvertGuidToShow",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58E470,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsTBFinalServer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FA60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsZbsSpeicalServer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FAA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsZbs2018SpeicalServer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FAE0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsZbsCloseVote_2018",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FB20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "IsDfsSpeicalServer",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FB60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "CheckCurrentProcedure",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58EAF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetDataByBinary",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FDB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "OtherPlayerHaveImpact",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58FE80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ShowOldFriend_Gift",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591530,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_HideOldFriend_Gift",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5915C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SetBieYeFurniture",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591560,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_RemoveBieYeFurniture",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5915F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ShowBieYeFurniture",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591610,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ShowBieYeFurniture_InBank",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591630,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_HCBieYeFurniture",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591650,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ZHBieYeFurniture",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591670,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_RCBieYeFurniture",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591690,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ShowBieYeMengChong",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591710,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_LeaveHCBieYeFurniture",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5916B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetZhaoHuiCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5919D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_EnumZhaoHuiData",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591A20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetFuBenIdxByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591CC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SendAskNewServerBroadcastMsg",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591730,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ReportWaigua",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591820,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_RemoveBieYeMengChong",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5916D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_CallOut",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5916F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetBitValueInUINT",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591D40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetBitValueInUINT",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591E50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "SetFakeObjDataEx",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_591FD0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetTitleListElement",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5920B0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_InitTitleTable",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592050,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SortTitle",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592040,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetTitleElementSize",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5921E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetTitleListElementByIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592220,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCaplockStatus",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592810,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetActiveInput",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592850,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetCameraDir",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592890,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_HasSelectedZNQfudai",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5928E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_AskZNQfudaiInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592960,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetZNQfudaiCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592A70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetZNQfudaiInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592B00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ZNQfudaiAddItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592C80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ZNQfudaiClean",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592D20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ZNQfudaiSendInsert",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592D30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetZNQfudaiInfoByBonusId",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592F20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetMyZNQItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_592EA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetMyZNQCurrency",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593070,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_IsZNQBonusSelected",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5930F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_IsZNQBonusAllSelected",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593170,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetZNQBonusSelectedCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5931D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ToggleZNQBugTokens",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593230,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_HasSelectedGQHYChouJiang",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593570,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_AskGQHYChouJiangInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5935F0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetGQHYChouJiangCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593700,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetGQHYChouJiangInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593790,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GQHYChouJiangAddItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593920,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GQHYChouJiangClean",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593910,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GQHYChouJiangSendInsert",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5939C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetGQHYChouJiangInfoByBonusId",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593BB0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetMyGQHYChouJiangItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593B30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetMyGQHYChouJiangCurrency",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593D00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_IsGQHYChouJiangBonusSelected",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593D80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_IsGQHYChouJiangBonusAllSelected",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593E00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetGQHYChouJiangBonusSelectedCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593E60,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ToggleGQHYChouJiangBuyTokens",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593EC0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetDuanWuItemInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593F20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetDuanWuIsSelected",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594080,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetSelectedAward",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594130,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_IsDWReceived",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5942D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetDWSelectNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594360,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetDWNotFullIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594410,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetSelectedAwardByTableIndex",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594950,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetDWReceivedNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594AA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_IsDWFanLiReceived",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594B00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetDWFanLiNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594BA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetNationalShopItemInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_593290,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetNationalShopItemCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5934D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_FlappyBird_Init",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594C00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_FlappyBird_SetCube",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594CF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_FlappyBird_MoveUpdate",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594E30,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFnOpenXingZhen",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_594F40,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFnOpenTargetXingZhen",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_595550,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFnOpenXingZhenChip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5951A0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFnOpenXingZhenUpgrade",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_595210,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFnOpenXingZhenSkill",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_595240,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFnShowXingZhenSlotTip",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_595270,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetHuiLiuShopItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5955E0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_ParseBit",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_595BF0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetJiebanShopItem",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5957D0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetJiebanShopItemCount",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_595970,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetJiebanShopLimit",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_595A70,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "MessageBoxSelf3",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_595C90,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFnSkillCardRecycleConfirm",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_5963C0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFnOpenSkillCardDetail",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_595570,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaFnGetSHShopItemQual",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_596420,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "GetHuoyueDaibiCleanTime",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_596560,
    0);
  LuaPlus::LuaObject::CreateTable(&v659, &v653, "OSAPIMetaTable", 0, 0);
  LOBYTE(v660) = 1;
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v653, "__index", (struct LuaPlus::LuaObject *)&v653);
  sub_877220((LuaPlus::LuaObject *)&v653, "GetTickCount", (int)sub_630A80, 0);
  sub_877220((LuaPlus::LuaObject *)&v653, "timeGetTime", (int)sub_630AC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v653, "OutputDebugString", (int)sub_630B00, 0);
  v6 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v454, &unk_D31AB8);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v645, v6);
  LOBYTE(v660) = 2;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v645, (const struct LuaPlus::LuaObject *)&v653);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "OSAPI", (struct LuaPlus::LuaObject *)&v645);
  LuaPlus::LuaObject::CreateTable(&v659, &v652, "FPUMetaTable", 0, 0);
  LOBYTE(v660) = 3;
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v652, "__index", (struct LuaPlus::LuaObject *)&v652);
  sub_877220((LuaPlus::LuaObject *)&v652, "Set53bitControlWord", (int)sub_60BD80, 0);
  sub_877220((LuaPlus::LuaObject *)&v652, "RestoreLastSetControlWord", (int)sub_60BDB0, 0);
  v7 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v408, &unk_D2E220);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v552, v7);
  LOBYTE(v660) = 4;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v552, (const struct LuaPlus::LuaObject *)&v652);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "FPU", (struct LuaPlus::LuaObject *)&v552);
  LuaPlus::LuaObject::CreateTable(&v659, &v654, "ExcitPointMetaTable", 0, 0);
  LOBYTE(v660) = 5;
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v654, "__index", (struct LuaPlus::LuaObject *)&v654);
  sub_877220((LuaPlus::LuaObject *)&v654, "GetTotalCount", (int)sub_609530, 0);
  sub_877220((LuaPlus::LuaObject *)&v654, "GetTotalTableIndexByIndex", (int)sub_6095D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v654, "GetVisableCount", (int)sub_609690, 0);
  sub_877220((LuaPlus::LuaObject *)&v654, "GetVisableTableIndexByIndex", (int)sub_609740, 0);
  sub_877220((LuaPlus::LuaObject *)&v654, "GetItemByTableIndex", (int)sub_609800, 0);
  v8 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v452, &unk_D2E1F0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v554, v8);
  LOBYTE(v660) = 6;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v554, (const struct LuaPlus::LuaObject *)&v654);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "ExcitPoint", (struct LuaPlus::LuaObject *)&v554);
  LuaPlus::LuaObject::CreateTable(&v659, &v656, "AuctionMetaTable", 0, 0);
  LOBYTE(v660) = 7;
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v656, "__index", (struct LuaPlus::LuaObject *)&v656);
  sub_877220((LuaPlus::LuaObject *)&v656, "PacketSend_Search", (int)sub_59DC10, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetItemAuctionInfo", (int)sub_59F100, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetPetAuctionInfo", (int)sub_59F220, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "PacketSend_SellPet", (int)sub_59DE20, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "PacketSend_SellItem", (int)sub_59DF70, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "OpenUpPetWindow", (int)sub_59F3D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "OpenUpItemWindow", (int)sub_59F3F0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "OpenOnSaleWindow", (int)sub_59F410, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "CloseUpPetWindow", (int)sub_59F430, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "CloseUpItemWindow", (int)sub_59F450, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "CloseOnSaleWindow", (int)sub_59F470, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "AskAuctionBoxList", (int)sub_59F490, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "SetPageItemSelect", (int)sub_59E380, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "PacketSend_MultiBuy", (int)sub_59E420, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "PacketSend_Buy", (int)sub_59E100, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetPetList_Appoint", (int)sub_59F350, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetBackWhatOnSale", (int)sub_59F510, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetBackExpired", (int)sub_59F6C0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetMySellBoxPetAuctionInfo", (int)sub_59F820, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetMySellBoxItemAuctionInfo", (int)sub_59F970, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetMyAuctionSellBoxPetGuid", (int)sub_59FAC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetMyAuctionSellBoxItemGuid", (int)sub_59FBB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetPetPortraitByIndex", (int)sub_59FCC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "ShowYBMarketCurPage_PetInfo", (int)sub_59FDF0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "ShowMySellBox_PetInfo", (int)sub_59FE70, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetMoney", (int)sub_59FEF0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetNeedMoneyForSell", (int)sub_5A0080, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetMySellBoxItemName", (int)sub_5A0100, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "OpenChangePriceWindow", (int)sub_5A0200, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "ChangePrice", (int)sub_5A02B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetMySellBoxItemNum", (int)sub_5A04B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "IsYBMarketCanSwitchPage", (int)sub_5A0540, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "GetPetEraCount", (int)sub_5A05B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v656, "ReUpExpired", (int)sub_5A0680, 0);
  v9 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v374, &unk_D2DCD4);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v556, v9);
  LOBYTE(v660) = 8;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v556, (const struct LuaPlus::LuaObject *)&v656);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Auction", (struct LuaPlus::LuaObject *)&v556);
  LuaPlus::LuaObject::CreateTable(&v659, &v655, "KVKAuctionMetaTable", 0, 0);
  LOBYTE(v660) = 9;
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v655, "__index", (struct LuaPlus::LuaObject *)&v655);
  sub_877220((LuaPlus::LuaObject *)&v655, "PacketSend_Search", (int)sub_61BBE0, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "GetItemAuctionInfo", (int)sub_61BDF0, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "PacketSend_Buy", (int)sub_61C120, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "SetPageItemSelect", (int)sub_61C390, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "PacketSend_MultiBuy", (int)sub_61C420, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "OpenUpItemWindow", (int)sub_61D0C0, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "OpenOnSaleWindow", (int)sub_61D130, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "GetNeedMoneyForSell", (int)sub_61D150, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "PacketSend_SellItem", (int)sub_61D240, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "AskAuctionBoxList", (int)sub_61D400, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "GetMySellBoxItemAuctionInfo", (int)sub_61D480, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "ReUpExpired", (int)sub_61D670, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "GetBackExpired", (int)sub_61D7D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "GetMoney", (int)sub_61D930, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "GetBackWhatOnSale", (int)sub_61DAC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "OpenChangePriceWindow", (int)sub_61DC70, 0);
  sub_877220((LuaPlus::LuaObject *)&v655, "ChangePrice", (int)sub_61DD20, 0);
  v10 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v450, &unk_D31928);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v558, v10);
  LOBYTE(v660) = 10;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v558, (const struct LuaPlus::LuaObject *)&v655);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "KVKAuction", (struct LuaPlus::LuaObject *)&v558);
  LuaPlus::LuaObject::CreateTable(&v659, &v657, "CharacterMetaTable", 0, 0);
  LOBYTE(v660) = 11;
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v657, "__index", (struct LuaPlus::LuaObject *)&v657);
  sub_877220((LuaPlus::LuaObject *)&v657, "SelectThePlayer", (int)sub_5B3190, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "IsPresent", (int)sub_877659, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetName", (int)sub_87764B, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetFullName", (int)sub_87768B, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetHPPercent", (int)sub_5B3510, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetMPPercent", (int)sub_5B3580, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetTPPercent", (int)sub_5B35F0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetRagePercent", (int)sub_5B3680, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetEngPercent", (int)sub_5B3700, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetMenPai", (int)sub_5B37D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Follow", (int)sub_5B4780, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetPos", (int)sub_877655, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetMyPos", (int)sub_5B49D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetSOState", (int)sub_5B3930, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "ForbidIt", (int)sub_5B3990, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Lua_ForbidItConfirm", (int)sub_5B3AC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "KickItOut", (int)sub_5B3D40, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Lua_ForbidItByName", (int)sub_5B3F70, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "ReportWaiguaForInfo", (int)sub_5B4100, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "OpenOtherWebClient", (int)sub_877650, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetLevel", (int)sub_5B4FE0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetData", (int)sub_5B5060, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "CanGetTargetEquip", (int)sub_5B6420, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendAskDetail", (int)sub_5B6460, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Set_To_Private", (int)sub_5B6B20, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Close_Before_TargetEquip_UI", (int)sub_5B6C00, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetEquip_ChangeModel", (int)sub_5B6C20, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetEquip_DestroyUIModel", (int)sub_5B6CE0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_ChangeModel", (int)sub_5B6D10, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Model_Team", (int)sub_5B6D80, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Model_Raid", (int)sub_5B6E10, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_DestoryUIModel", (int)sub_5B6D70, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "AdjustHeadCamera", (int)sub_5B6E60, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendTeamRequest", (int)sub_5B4230, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendTeamApply", (int)sub_5B4590, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetBuffNumber", (int)sub_87765E, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetBuffIconNameByIndex", (int)sub_877668, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetBuffPriorityByIndex", (int)sub_87766D, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetDialogNpcName", (int)sub_877672, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetShopNpcName", (int)sub_877677, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetXinfaNpcName", (int)sub_87767C, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetServerId2ClientId", (int)sub_5B6C30, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "IsTransferMode", (int)sub_877663, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetNpcName", (int)sub_877681, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "IsTargetTeamMember", (int)sub_5B78D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "IsTargetValide", (int)sub_5B7910, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Name_Team", (int)sub_5B7960, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_GetTitleType", (int)sub_5B79C0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_HP_Team", (int)sub_5B7A40, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_MP_Team", (int)sub_5B7AA0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_TP_Team", (int)sub_5B7B00, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Rage_Team", (int)sub_5B7B60, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Eng_Team", (int)sub_5B7BC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Level_Team", (int)sub_5B7C20, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Icon_Team", (int)sub_5B7C80, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_HeadFrame_Team", (int)sub_5B7CE0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Menpai_Team", (int)sub_5B7D30, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SetHorseModel", (int)sub_877686, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "CharRnameCheck", (int)sub_5B7D90, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendCharRnameMsg", (int)sub_5B8060, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "CharRnameConfirm", (int)sub_5B81A0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendChangeNameMsg", (int)sub_5B8290, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "ChangeNameConfirm", (int)sub_5B83D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendUpdateVipInfoMsg", (int)sub_5B9EB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendRaidInvitation", (int)sub_5B90C0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendRaidApplication", (int)sub_5B9470, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Name_Raid", (int)sub_5B9770, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_HP_Raid", (int)sub_5B97D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_MP_Raid", (int)sub_5B9880, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_TP_Raid", (int)sub_5B9930, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Rage_Raid", (int)sub_5B99E0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Eng_Raid", (int)sub_5B9A50, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Level_Raid", (int)sub_5B9AC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Icon_Raid", (int)sub_5B9B40, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Menpai_Raid", (int)sub_5B9BF0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "IsTargetRaidMember", (int)sub_5B9C70, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetTargetGUID", (int)sub_5B9CB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_HeadFrame_Raid", (int)sub_5B9D60, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetNobilityInfo", (int)sub_5BAAB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "LuaFnGetActivedXingJuanID", (int)sub_5BAE80, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "LuaFnGetXingJuanInfo", (int)sub_5BAF30, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "LuaFnGetActivedSkillCardID", (int)sub_5BB280, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "LuaFnGetSkillCardInfo", (int)sub_5BB330, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "LuaFnGetXingZhen_JiBanTotalAttr", (int)sub_5BB660, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "LuaFnXingJuanCollection", (int)sub_5BB770, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "LuaFnSkillCardCollection", (int)sub_5BB940, 0);
  v11 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v406, off_C661A4);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v560, v11);
  LOBYTE(v660) = 12;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v560, (const struct LuaPlus::LuaObject *)&v657);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Target", (struct LuaPlus::LuaObject *)&v560);
  LuaPlus::LuaObject::CreateTable(&v659, &v551, "CachedCharacterMetaTable", 0, 0);
  LOBYTE(v660) = 13;
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v657, "__index", (struct LuaPlus::LuaObject *)&v657);
  sub_877220((LuaPlus::LuaObject *)&v657, "IsPresent", (int)sub_877659, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetName", (int)sub_87764B, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetZoneWorldId", (int)sub_5B9E30, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetHPPercent", (int)sub_5B3510, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetMPPercent", (int)sub_5B3580, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetRagePercent", (int)sub_5B3680, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Follow", (int)sub_5B4780, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetPos", (int)sub_877655, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetLevel", (int)sub_5B4FE0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetData", (int)sub_5B5060, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetSkillDesc", (int)sub_5B6310, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "CanGetTargetEquip", (int)sub_5B6420, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendAskDetail", (int)sub_5B6460, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Set_To_Private", (int)sub_5B6B20, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Close_Before_TargetEquip_UI", (int)sub_5B6C00, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetEquip_ChangeModel", (int)sub_5B6C20, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetEquip_DestroyUIModel", (int)sub_5B6CE0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetEquipMasterFlag", (int)sub_5B70B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetIsBaiShouFlag", (int)sub_5B7110, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetChangyigeCheckMsg", (int)sub_5B71D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetMySelfEquipMasterFlag", (int)sub_5B7170, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetDress_ChangeModel", (int)sub_5B6CF0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetDress_DestroyUIModel", (int)sub_5B6D00, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendTeamRequest", (int)sub_5B4230, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendTeamApply", (int)sub_5B4590, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetBuffNumber", (int)sub_87765E, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetBuffIconNameByIndex", (int)sub_877668, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetBuffPriorityByIndex", (int)sub_87766D, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetDialogNpcName", (int)sub_877672, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetShopNpcName", (int)sub_877677, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetXinfaNpcName", (int)sub_87767C, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetServerId2ClientId", (int)sub_5B6C30, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "IsTargetTeamMember", (int)sub_5B78D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "IsTargetValide", (int)sub_5B7910, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Name_Team", (int)sub_5B7960, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_HP_Team", (int)sub_5B7A40, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_MP_Team", (int)sub_5B7AA0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Rage_Team", (int)sub_5B7B60, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Level_Team", (int)sub_5B7C20, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Icon_Team", (int)sub_5B7C80, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_HeadFrame_Team", (int)sub_5B7CE0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Menpai_Team", (int)sub_5B7D30, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SetHorseModel", (int)sub_877686, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "CharRnameCheck", (int)sub_5B7D90, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendCharRnameMsg", (int)sub_5B8060, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "CharRnameConfirm", (int)sub_5B81A0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetKfsData", (int)sub_5B8500, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetKfsFixAttrEx", (int)sub_5B8DB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetKfsBase", (int)sub_5B8F10, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetFixKfsBase", (int)sub_5B8FC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "UpdateOtherKFSModel", (int)sub_5B90B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Lua_GetTargetEnchanceMinLevel", (int)sub_5B9F40, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Lua_GetHXYGrade", (int)sub_5B9FD0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Lua_GetHXYLevel", (int)sub_5BA0A0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Lua_GetHXYEffect", (int)sub_5BA130, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Lua_GetHXYExAttrInfo", (int)sub_5BA3B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Lua_GetHXYEffectRefixValue", (int)sub_5BA5E0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "Lua_GetHXYExAttrRefixValue", (int)sub_5BA910, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "CheckSuperWeapon9", (int)sub_5B8900, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "CheckSuperWeaponTopo", (int)sub_5B8970, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "CheckSuperWeaponDIYSkillData", (int)sub_5B89E0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetSuperWeaponDIYSkillData", (int)sub_5B8A60, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetSuperWeaponNameAndQual", (int)sub_5B8C40, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetTargetSuperWeaponDIYSkillActive", (int)sub_5B8D20, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendRaidInvitation", (int)sub_5B90C0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "SendRaidApplication", (int)sub_5B9470, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Name_Raid", (int)sub_5B9770, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_HP_Raid", (int)sub_5B97D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_MP_Raid", (int)sub_5B9880, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Rage_Raid", (int)sub_5B99E0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Level_Raid", (int)sub_5B9AC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Icon_Raid", (int)sub_5B9B40, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_Menpai_Raid", (int)sub_5B9BF0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "IsTargetRaidMember", (int)sub_5B9C70, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "GetTargetGUID", (int)sub_5B9CB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v657, "TargetFrame_Update_HeadFrame_Raid", (int)sub_5B9D60, 0);
  v12 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v453, &off_C661A8);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v562, v12);
  LOBYTE(v660) = 14;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v562, (const struct LuaPlus::LuaObject *)&v657);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "CachedTarget", (struct LuaPlus::LuaObject *)&v562);
  LuaPlus::LuaObject::CreateTable(&v659, &v658, "PlayerMySelfMetaTable", 0, 0);
  LOBYTE(v660) = 15;
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v658, "__index", (struct LuaPlus::LuaObject *)&v658);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetGUID", (int)sub_64F260, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetData", (int)sub_8776A0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetPos", (int)sub_877655, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetMyPos", (int)sub_5B49D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsPresent", (int)sub_877659, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetName", (int)sub_87764B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetBuffNumber", (int)sub_87765E, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetBuffIconNameByIndex", (int)sub_877668, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetBuffPriorityByIndex", (int)sub_87766D, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetBuffToolTipsByIndex", (int)sub_8777AB, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "DispelBuffByIndex", (int)sub_8777B3, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetBuffTimeTextByIndex", (int)sub_8777BB, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetAccMD5String", (int)sub_65B320, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetAbilityInfo", (int)sub_8776A5, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetSkillInfo", (int)sub_8776AA, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetXinfaInfo", (int)sub_8776AF, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetXiuLianMiJiInfo", (int)sub_8776B4, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetXiuLianBookInfo", (int)sub_8776B9, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetMifaInfo", (int)sub_8776BE, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetOtherMifaInfo", (int)sub_8776C3, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetMySex", (int)sub_8776C8, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GeTargetSex", (int)sub_8776CD, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetMifaActiveXueWei", (int)sub_8776D2, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetComboBookInfo", (int)sub_8776D7, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetZhenFaTotalpoint", (int)sub_65F490, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetStrZhenfaSkill", (int)sub_65F5B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetZhenfaAttr", (int)sub_65FAB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetZhenfareturnback", (int)sub_6601C0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetZhenFaDemand", (int)sub_65FDB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "AgnameChangeTime", (int)sub_65FEE0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetOtherComboBookInfo", (int)sub_8776DC, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetOtherXiuwei", (int)sub_8776E1, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "AskLeanAbility", (int)sub_8776E6, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetAgnameNum", (int)sub_8776EB, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "EnumOwnerTitles", (int)sub_8776F3, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetOwnerIndexByTitleID", (int)sub_8776FB, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetSystemColorText", (int)sub_877703, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "EnumBoardType", (int)sub_87770B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "EnumAgname", (int)sub_877713, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetCurrentAgname", (int)sub_877723, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetTiTleInFoTbl", (int)sub_87771B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "AskChangeCurrentAgname", (int)sub_87772B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SetNullAgname", (int)sub_64F350, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "DisplayNvShenTitle", (int)sub_87777B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "HaveTitle", (int)sub_8777A3, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendReportMsg", (int)sub_65BCC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "ReportLoginTypeMsg", (int)sub_65C2D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetCurrentVirtualAgname", (int)sub_877753, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetCurrentVirtualAgnameType", (int)sub_87775B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "AskChangeCurrentEffect", (int)sub_877763, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "EnumFlashType", (int)sub_877773, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetTitleDisableTime", (int)sub_87776B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetYueliNum", (int)sub_877783, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetYueliItem", (int)sub_87778B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetCurAgYueLi", (int)sub_877793, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetAllTitlesNum", (int)sub_877733, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "EnumAllTitles", (int)sub_87773B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsNeedShowYueLiAttr", (int)sub_87779B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetMaxTitleIndex", (int)sub_877743, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetShowUITitleCnt", (int)sub_87774B, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendAskManualAttr", (int)sub_650F90, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetCurTitle", (int)sub_64F2F0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "AgreeJoinTeam", (int)sub_64FFA0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "RejectJoinTeam", (int)sub_650110, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendAgreeJoinTeam_Apply", (int)sub_650260, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendRejectJoinTeam_Apply", (int)sub_6503A0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendAgreeJoinTeam_TeamMemberInvite", (int)sub_6504E0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendRejectJoinTeam_TeamMemberInvite", (int)sub_6506B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendAgreeJoinGroup", (int)sub_650CA0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendRefuseJoinGroup", (int)sub_650DB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendAgreeTeamFollow", (int)sub_650880, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendRefuseTeamFollow", (int)sub_650940, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "LeaveTeam", (int)sub_64F380, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "DismissTeam", (int)sub_64F3B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "OpenDismissTeamMsgbox", (int)sub_64F3F0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "ConfirmDismissTeam", (int)sub_64F410, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "KickTeamMember", (int)sub_64F430, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "CreateTeamSelf", (int)sub_64F510, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "ChangePVPMode", (int)sub_64F6C0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "ChangePVPModeWithPassword", (int)sub_64F790, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "PVP_Duel", (int)sub_64FB10, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "PVP_ShowMenu", (int)sub_64F8C0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "PVP_Challenge", (int)sub_64FB50, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "AppointLeader", (int)sub_64FCB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "InTeamFollowMode", (int)sub_64FD20, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "StopFollow", (int)sub_64FD70, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "TeamFrame_AskTeamFollow", (int)sub_64FE50, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetTeamMemberGUID", (int)sub_650A80, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetTeamMemberName", (int)sub_650BA0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetTeamMemberZoneWorldID", (int)sub_650EC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendReliveMessage_OutGhost", (int)sub_8777C3, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendReliveMessage_Fool", (int)sub_8777D3, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendReliveMessage_Relive", (int)sub_8777CB, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SetSupperPassword", (int)sub_659350, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetTotalHorseNum", (int)sub_6593A0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetMyHorse", (int)sub_659440, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SetHorseModel", (int)sub_877686, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsOnHorse", (int)sub_659590, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "DrawSwearTitle", (int)sub_877690, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "ChangeSwearTitle", (int)sub_877698, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "CheckSwearTitle", (int)sub_659970, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SetExpAssgin", (int)sub_659AE0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsLeader", (int)sub_659BD0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetReputation", (int)sub_659C80, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetPKMode", (int)sub_651140, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetTimeToPeace", (int)sub_651190, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsInTeam", (int)sub_659C40, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "ShowMySelfContexMenu", (int)sub_8777DB, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SelectMyselfAsTarget", (int)sub_8777E3, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "YuanBaoToTicket", (int)sub_659D30, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "YuanBaoToBind", (int)sub_659F40, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsHavePassword", (int)sub_65A070, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsLocked", (int)sub_65A130, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendSpeakerMessage", (int)sub_65A1F0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "UseRose", (int)sub_65A530, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "UseItem", (int)sub_65B6C0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SetIPRegion", (int)sub_65A890, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetDenaAttr", (int)sub_65A960, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "CheckIfCanDena", (int)sub_65AA20, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetPlayerActionStatus", (int)sub_65AB30, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetPlayerChangeModel", (int)sub_65AC10, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetPlayerShopDresserStatus", (int)sub_65ABC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetMountID", (int)sub_65AC70, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "UseSkillInLua_Const", (int)sub_65ACD0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsPlayerInFittingState", (int)sub_65AEB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "UseSkill", (int)sub_65AF10, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "UseSkillnew", (int)sub_65B040, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "DelDenaObj", (int)sub_65B1E0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "CreateDenaObj", (int)sub_65B190, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SaveDenaAttr", (int)sub_65B200, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "ClearUpdateBtnFlashFlag", (int)sub_65B410, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetLevelMoneyLimit", (int)sub_65B4D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetLevel", (int)sub_65B5D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsVaild", (int)sub_65B660, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsHaveItem", (int)sub_65BA60, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "CommonClientMessage", (int)sub_65BB30, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendAcceptRaidInvitation", (int)sub_65C6A0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendRejectRaidInvitation", (int)sub_65C7E0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendAgreeRaidApplication", (int)sub_65C910, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SendOpposeRaidApplication", (int)sub_65CB50, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "LeaveRiad", (int)sub_65CD90, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "KickRaidMemberByIdx", (int)sub_65CE40, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "CreateRaidSelf", (int)sub_65D2D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "RaidAppointByIdx", (int)sub_65D4E0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsRaidLeader", (int)sub_65D880, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "Player_GetTitleType", (int)sub_65D8F0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsRaidAssitant", (int)sub_65D940, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsInRaid", (int)sub_65D9B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "ShowRaidApplicationList", (int)sub_65DA00, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetMyRaidIndex", (int)sub_65DA50, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "OpenCreateRaidConfirmWindow", (int)sub_65DB30, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsHaveCurrentPet", (int)sub_65DC40, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "CreateCorps", (int)sub_65DCA0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "WeekcardTakeTimes", (int)sub_65DEB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SetServiceState", (int)sub_65DEF0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetServiceState", (int)sub_65DF50, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SetMCardIndex", (int)sub_65DF90, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "SetMCardIndexShow", (int)sub_65DFF0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetPetMasterPointState", (int)sub_65E050, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetOtherPetMasterPointState", (int)sub_65E300, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetPetMasterPointEffect", (int)sub_65E540, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetPetMasterTotalEffect", (int)sub_65E6D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetOtherPetMasterTotalEffect", (int)sub_65E850, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsPetMasterEffectActive", (int)sub_65E9D0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsOtherPetMasterEffectActive", (int)sub_65EAC0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetBrotherShip", (int)sub_65F3B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetWeekBrotherShip", (int)sub_65F400, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetMaxWeekBrotherShip", (int)sub_65F450, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsFiveElements_ElementsActive", (int)sub_65EBB0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "IsOtherFiveElements_ElementsActive", (int)sub_65EC40, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetFiveElements_ElementsType", (int)sub_65ECD0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetOtherFiveElements_ElementsType", (int)sub_65ED60, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetFiveElements_ElementsLevel", (int)sub_65EDF0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetOtherFiveElements_ElementsLevel", (int)sub_65EE80, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetFiveElements_JadeType", (int)sub_65EF10, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetOtherFiveElements_JadeType", (int)sub_65EFD0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetFiveElements_JadeExtend", (int)sub_65F090, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetOtherFiveElements_JadeExtend", (int)sub_65F1A0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "GetFiveElementsIndexCanDoCohesion", (int)sub_65F2B0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "Lua_GetXbwData_2018", (int)sub_6602E0, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "Lua_GetOtherXbwData_2018", (int)sub_660770, 0);
  sub_877220((LuaPlus::LuaObject *)&v658, "AskWLZDRankingList", (int)sub_660BD0, 0);
  v13 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v462, &dword_D31D0C);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v647, v13);
  LOBYTE(v660) = 16;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v647, (const struct LuaPlus::LuaObject *)&v658);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Player", (struct LuaPlus::LuaObject *)&v647);
  v14 = operator new(0x18u);
  v465 = v14;
  LOBYTE(v660) = 17;
  if ( v14 )
    v15 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v14);
  else
    v15 = 0;
  dword_D2D010 = v15;
  LOBYTE(v660) = 16;
  v16 = LuaPlus::LuaObject::CreateTable(&v659, &v546, "ActionButtonMetaTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2D010, v16);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v546);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2D010,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2D010);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "IsEnable", (int)sub_405A10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetID", (int)sub_404E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetType", (int)sub_404E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetName", (int)sub_404EA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetOwnerXinfa", (int)sub_4053F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetPetSkillOwner", (int)sub_405510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetDefineID", (int)sub_4053B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetPrice", (int)sub_405570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetNum", (int)sub_4055B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetDesc", (int)sub_404ED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "CheckMenPaiLimit", (int)sub_4055F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "Lua_CheckRenaWaTime", (int)sub_4056B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipDur", (int)sub_405730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipDurValue", (int)sub_4057B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetStrengthenLevel", (int)sub_405820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "IsActionFlash", (int)sub_405910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipPoint", (int)sub_405990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemColorInShop", (int)sub_404F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemID", (int)sub_405A50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetOwnerItemID", (int)sub_405AB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "SetActionFlash", (int)sub_405940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "IsLevelEnoughEquip", (int)sub_405B10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "IsLevelEnoughEquip_Target", (int)sub_405B50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetRemainRepairCount", (int)sub_405B90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAttaProperty", (int)sub_4067C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAttaPropertyOnly", (int)sub_4069B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAttaTransferInfo", (int)sub_406CE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAttaBaseValue", (int)sub_406BC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "EnumEquipExtAttr", (int)sub_407060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAttrCount", (int)sub_407000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "EquipCanRecoin", (int)sub_4071C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipDecompose", (int)sub_4061A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "EquipCanDecompose", (int)sub_406080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemIconInShop", (int)sub_404FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetMaxNum", (int)sub_406040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemTableIndex", (int)sub_405FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemBuyRateInShop", (int)sub_405060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemColorInFittingRoom", (int)sub_405C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemIconInFittingRoom", (int)sub_405D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemPriceInFittingRoom", (int)sub_405E10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemSourceShopUnitInFittingRoom", (int)sub_405EB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemSourceShopIDInFittingRoom", (int)sub_405F50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemColorInShop_JiYuan", (int)sub_4050F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemIconInShop_JiYuan", (int)sub_4051A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemColorInShop_Recent", (int)sub_405250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetItemIconInShop_Recent", (int)sub_405300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEnhanceAttAndDef", (int)sub_406A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipGemLevel", (int)sub_4072D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipGemSlotNum", (int)sub_407350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "IsEquipHaveZiZhi", (int)sub_407390, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipMaxAttrByAptRate", (int)sub_4073F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipMaxAttrByAptValue", (int)sub_407450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "SetSelectStatus", (int)sub_4074B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "SetLockStatus", (int)sub_407520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "Lua_GetEquipZhiZunType", (int)sub_406750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "Lua_IsCanFuke", (int)sub_406370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "Lua_GetEquipAttaFuKeInfo", (int)sub_406410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipLevel", (int)sub_407590, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipQuality", (int)sub_407610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipIsSuperWeapon", (int)sub_407690, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipGemInfo", (int)sub_407710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipIsLocked", (int)sub_407880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipDiaoWen", (int)sub_407900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipLongWenInfo", (int)sub_407A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipJingTongInfo", (int)sub_407BD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipLingPaiInfo", (int)sub_407CE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAnqiQuality", (int)sub_407E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipKfsAttrInfo", (int)sub_408190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipTableLevel", (int)sub_4083B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipHXYLevel", (int)sub_408480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAnqiLYStar", (int)sub_407F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAnqiLYCDHP", (int)sub_407F90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAnqiLYCDPro", (int)sub_408010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAnqiLYCDHit", (int)sub_408110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D010, "GetEquipAnqiLYCDProType", (int)sub_408090, 0);
  v17 = operator new(0x18u);
  v465 = v17;
  LOBYTE(v660) = 18;
  if ( v17 )
    v18 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v17);
  else
    v18 = 0;
  dword_D2DEF4 = v18;
  LOBYTE(v660) = 16;
  v19 = LuaPlus::LuaObject::CreateTable(&v659, &v506, "DataPoolMetaTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DEF4, v19);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v506);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DEF4,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DEF4);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionInfo_Num", (int)sub_5C88D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionInfo_Text", (int)sub_5C8940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionInfo_Bonus", (int)sub_5C89B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionInfo_Kind", (int)sub_5C8C60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionInfo_ScriptID", (int)sub_5C8D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionDemand_Num", (int)sub_5C8DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CloseMissionFrame", (int)sub_5C8E10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionDemand_Text", (int)sub_5C8E90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionDemand_Item", (int)sub_5C8F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionContinue_Num", (int)sub_5C8FC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionContinue_Text", (int)sub_5C9030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionContinue_Bonus", (int)sub_5C90A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionContinue_ScriptID", (int)sub_5C9200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionContinue_MissionID", (int)sub_5C9240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionContinue_IssueScriptID", (int)sub_5C9280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionContinue_ItemID", (int)sub_5C92C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_Num", (int)sub_5C9360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_InUse", (int)sub_5C93A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_Description", (int)sub_5C9470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionCustom_Num", (int)sub_5CA800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionCustom", (int)sub_5CA8C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_DataRound", (int)sub_5CBA40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Mission_Abnegate_Popup", (int)sub_5CB820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "EnumPlayerMission_ItemAction", (int)sub_5CB9B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Mission_Abnegate_Special_Quest_Popup", (int)sub_5CB910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_DataCountByte", (int)sub_5CBB20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_DataBinary", (int)sub_5CBBF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionRandomCustom_Num", (int)sub_5CAF60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionRandomCustom", (int)sub_5CB010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_ItemCountNow", (int)sub_5CB140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_BillName", (int)sub_5CAE30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_Name", (int)sub_5CAD70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_Info", (int)sub_5CAF00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_Variable", (int)sub_5CB410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsHaveMission", (int)sub_5CB1D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsMissionHaveDone", (int)sub_5CB250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionIndexByID", (int)sub_5CB390, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetMissionParam", (int)sub_5CB2D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_Display", (int)sub_5CB5D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_RemainTime", (int)sub_5CB710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_RemainTimeEx", (int)sub_5CB790, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionDemand_Num", (int)sub_5CA1C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionDemand_Item", (int)sub_5CA410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionDemandKill_Num", (int)sub_5CBCC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionDemand_NPC", (int)sub_5CBEC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionBonus_Num", (int)sub_5CA980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionBonus_Item", (int)sub_5CA9D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_Memo", (int)sub_5CABD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_Level", (int)sub_5CC240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_Kind", (int)sub_5CC2E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_IsElite", (int)sub_5CC380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_ForePart", (int)sub_5CC420, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_VariableByByte", (int)sub_5CC4C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_StrList", (int)sub_5CC600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMissionTrackType", (int)sub_5CD260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLuaMissionTrackInfo", (int)sub_5CD6B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetKillMonsterMissionTrackInfo_num", (int)sub_5CDAF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetKillMonsterMissionTrackInfo_MonsterInfo", (int)sub_5CDC60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLootItemMissionTrackInfo_num", (int)sub_5CE0B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLootItemMissionTrackInfo_ItemInfo", (int)sub_5CE220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetDeliveryMissionTrackInfo", (int)sub_5CD7A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetHusongMissionTrackInfo", (int)sub_5CE6C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "MissionTrackGotoQuestLog", (int)sub_5CE960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsMissionTrackOpen", (int)sub_5CE9C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetMissionTrackOpen", (int)sub_5CEA60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsTrackFuncShow", (int)sub_5CEB00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetTrackFuncShow", (int)sub_5CEBA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsCampaignTrackOpen", (int)sub_5CEC40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetCampaignTrackOpen", (int)sub_5CECD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CampaignTrackGotoCampaignList", (int)sub_5CED50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UpdateQuestLogByTrack", (int)sub_5CEDC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UpdateCampaignListByTrack", (int)sub_5CEDE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsCampaignCanTrack", (int)sub_5CEE00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UpdateMissionTrack", (int)sub_5CEE90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UpdateCampaignTrack", (int)sub_5CEEB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "HaveMisstionTrackThisType", (int)sub_5CEED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionFinishInfo", (int)sub_5CF250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UpdateTrackStateButton", (int)sub_5CF4C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMissionShortName", (int)sub_5CF520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetNPCEventList_Num", (int)sub_5C8680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetNPCEventList_Item", (int)sub_5C86C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCurrentMinorPwdTimes", (int)sub_5F5A10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetCurrentMinorPwdTimes", (int)sub_5F5A60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMinorPwdCurrentDayTime", (int)sub_5F5B70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetMinorPwdCurrentDayTime", (int)sub_5F5BC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCurrentCheckTimes", (int)sub_5F5AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetCurrentCheckTimes", (int)sub_5F5B10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "DateTime2DayTime", (int)sub_5D5340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetInfantExpMission", (int)sub_5F7540, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPrescrList_Num", (int)sub_5CFB60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPrescrList_Item", (int)sub_5CFBB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPrescrList_Item_LifeAbility", (int)sub_5CFC50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPrescrList_Item_Requirement", (int)sub_5CFDE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPrescrList_Item_Result", (int)sub_5CFD10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPrescrList_Item_LifeAbilityLevel", (int)sub_5CFFD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBoothList_Num", (int)sub_5D0070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBoothGood_ID", (int)sub_5D00C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBoothGood_Name", (int)sub_5D0170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBoothGood_Price", (int)sub_5D0220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ActiveMissionCue", (int)sub_5DF120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBaseBag_Num", (int)sub_5DF180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBaseBag_MaxNum", (int)sub_5DF1D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBaseBag_BaseNum", (int)sub_5DF210, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMatBag_Num", (int)sub_5DF250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMatBag_MaxNum", (int)sub_5DF2A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMatBag_BaseNum", (int)sub_5DF2E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTaskBag_Num", (int)sub_5DF320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTaskBag_MaxNum", (int)sub_5DF360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTaskBag_BaseNum", (int)sub_5DF3A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskMyBagList", (int)sub_5DF3E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFirstOpenSafeCenterFlag", (int)sub_5F4130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMobilePhoneConfigFlag", (int)sub_5F4180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMobileApproveStatus", (int)sub_5F41D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMobilePhoneNumber", (int)sub_5F4220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMobileApproveSecurityCode", (int)sub_5F4250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "DoMobileApprove", (int)sub_5F4300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMobileApprovePrize", (int)sub_5F4450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamMemberInfo", (int)sub_5D0620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamMemGUIDByUIIndex", (int)sub_5D0440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamMemNameByUIIndex", (int)sub_5D0540, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamMemInfoByIndex", (int)sub_5D19A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamMemberCount", (int)sub_5D0BA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamExpMode", (int)sub_5D0F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetTeamExpMode", (int)sub_5D0F50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamMemBufNum", (int)sub_5D1020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamMemBufInfo", (int)sub_5D10C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamMemBufPriority", (int)sub_5D11E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UpdateSceneMapPos", (int)sub_5D0C70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFeiZeiPos", (int)sub_5D0CF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsTeamLeader", (int)sub_5D0BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetInviteTeamCount", (int)sub_5D14C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetInviteTeamMemberCount", (int)sub_5D1880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetInviteTeamMemberInfo", (int)sub_5D1510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetSelectTeamMember_Leader", (int)sub_5D1940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetApplyMemberCount", (int)sub_5D3530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetApplyMemberInfo", (int)sub_5D3580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetCurSelApply", (int)sub_5D3880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "EraseApply", (int)sub_5D3910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ClearAllApply", (int)sub_5D3970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetTeamFrameOpenFlag", (int)sub_5D3990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetInviteTeamMemberUIModelName", (int)sub_5D1D10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamMemUIModelName", (int)sub_5D1DF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetApplyMemberUIModelName", (int)sub_5D1C80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamMemHeadUIModelName", (int)sub_5D1E80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetSelfInfo", (int)sub_5D1910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsTeamMemberInScene", (int)sub_5D1F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SelectAsTargetByUIIndex", (int)sub_5D0DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SelectTeamMemPetAsTargetByUIIndex", (int)sub_5D12F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "DarkAdjustAttr", (int)sub_5E1480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "DarkAdjustSkill", (int)sub_5E4E40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "DarkReset", (int)sub_5E4FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "DarkResetQuality", (int)sub_5E50C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ScriptPlus", (int)sub_5E5EA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipZiZhiDesc", (int)sub_5E16B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipZiZhiRefreshDesc", (int)sub_5E2000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipZiZhiCompare", (int)sub_5E2890, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipZiZhi", (int)sub_5E2BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPetEquipZiZhiNewDesc", (int)sub_5E3880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPetEquipZiZhiDesc", (int)sub_5E2F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetDarkSkillDesc", (int)sub_5E4110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetDarkSkillNewDesc", (int)sub_5E4460, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLYDarkSkillType", (int)sub_5E45E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLYDarkFreashSkillType", (int)sub_5E4730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CleanLYDarkFreashSkillType", (int)sub_5E4830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLYDarkStarInBag", (int)sub_5E4880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLYDarkCuiDuData", (int)sub_5E4930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLYDarkLianduCostDataInBag", (int)sub_5E4AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLYDarkStarAddDataInBag", (int)sub_5E4CD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSkillIconName", (int)sub_5E5220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSkillName", (int)sub_5E5320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSkillDesc", (int)sub_5E5420, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSuperWeaponDIYSkillDesc", (int)sub_5E5530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsSuperWeapon9", (int)sub_598F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsSuperWeaponTopo", (int)sub_598F80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsSuperWeapon9InBag", (int)sub_598FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsSuperWeaponTopoInBag", (int)sub_5990D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSuperWeaponDIYSkillActiveData", (int)sub_5991B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSuperWeaponDIYSkillLevelupData", (int)sub_599300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSuperWeaponDIYSkillId", (int)sub_599470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSuperWeaponDIYSkillSlotLevel", (int)sub_5994F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSuperWeaponDIYSkillImpactIndex", (int)sub_5995F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSuperWeaponDIYSkillIdInBag", (int)sub_5996F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSuperWeaponDIYSkillSlotLevelInBag", (int)sub_5997E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSuperWeaponDIYSkillImpactIndexInBag", (int)sub_5998E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetKFSSkillDesc", (int)sub_5E56E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetKFSNewSkillDesc", (int)sub_5E5B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetZhengZhaoFubenID", (int)sub_5D1FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetZhengZhaoCurIndex", (int)sub_5D1FE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetZhengZhaoAllCount", (int)sub_5D2030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetZhengZhaoCurPageCount", (int)sub_5D2080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetZhengZhaoInfo", (int)sub_5D20D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetZhengZhaoFubenCount", (int)sub_5D23B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetZhengZhaoFubenInfo", (int)sub_5D2430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetZZMemberInfoCount", (int)sub_5D2560, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetZZMemberInfo", (int)sub_5D25F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ApplyZhengZhaoInfo", (int)sub_5D2830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskZhengZhaoMemberInfo", (int)sub_5D2980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ApplyZhengZhaoTeam", (int)sub_5D2A90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ApplyZhengZhaoMsg", (int)sub_5D2BD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskHuiGuiZhengZhao", (int)sub_5D2CC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskHuiGuiTips", (int)sub_5D2FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SendHuiGuiZhengZhao", (int)sub_5D30E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "BindHuiGuiZhengZhao", (int)sub_5D33C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPacketItem", (int)sub_5D39F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPacketItemMaxNumber", (int)sub_5D3B40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFriendNumber", (int)sub_5D3B90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFriendOnlineNumber", (int)sub_5D3C10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFriendNumberCommon", (int)sub_5D3C90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFriendOnlineNumberCommon", (int)sub_5D3D10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFriend", (int)sub_5D3D90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ModifSnsTime", (int)sub_5D4D80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AddFriend", (int)sub_5D6C00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AddFriendAndGrouping", (int)sub_5D7CA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "InviteAddFriendByteam", (int)sub_5D6BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "InviteAddFriend", (int)sub_5D6BD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "InviteAddFriendByFriendList", (int)sub_5D6BE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "DelFriend", (int)sub_5D76C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskDelFriend", (int)sub_5D7AD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowFriendInfo", (int)sub_5D8D50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AddFoe", (int)sub_5D7EF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowFoeRelation", (int)sub_5D8200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "RefreshFoeTitle", (int)sub_5D8290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UpdateFriendInfo", (int)sub_5EEE50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCharIsAppAttention", (int)sub_5D8460, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCharSaletimeCyg", (int)sub_5D83E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTrustFriendNumber", (int)sub_5D5660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTrustFriend", (int)sub_5D56B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AddTrustFriend", (int)sub_5D58C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "DelTrustFriend", (int)sub_5D5BC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ToggleTrustFriendWindow", (int)sub_5D5CA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsTrustFriend", (int)sub_5D5CC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenDelTrustFriendCheckBox", (int)sub_5D5DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskBrotherInfo", (int)sub_5D5F80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBrotherCount", (int)sub_5D6010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBrotherInfoByInd", (int)sub_5D6060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSelfBrotherInfo", (int)sub_5D6380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LookupOtherParticularInfo", (int)sub_5D8FC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLookUpPartInfo", (int)sub_5DB8E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "InviteApplyAddPingbi", (int)sub_5DC870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowChatInfo", (int)sub_5D94A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowChatInfoByZWId", (int)sub_5D9610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetRemark", (int)sub_5D97B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetMood", (int)sub_5D9A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMood", (int)sub_5D9D10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "EditMood", (int)sub_5D8D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFriendByName", (int)sub_5DB410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFriendByGUID", (int)sub_5DB4F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenHistroy", (int)sub_5DB600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetProposerCount", (int)sub_5DB8A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMailNumber", (int)sub_5D9D80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMail", (int)sub_5D9DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenMail", (int)sub_5DA4D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenMailRead", (int)sub_5DA4A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ZhengYouOpenMail", (int)sub_5DA7C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SendMail", (int)sub_5DAAB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetNextMail", (int)sub_5DB370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenFriendList", (int)sub_5D9D50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMailTimeInt", (int)sub_5DA260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ThrowToBlackList", (int)sub_5D84C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ThrowToList", (int)sub_5D8750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenSystemHistroy", (int)sub_5DB680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSystemHistroyNumber", (int)sub_5DB850, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSystemHistroy", (int)sub_5DB6B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_MyHairColor", (int)sub_5DCAB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_MyHairStyle", (int)sub_5DCBE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_MyFaceStyle", (int)sub_5DCC40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_MyHairStyle_Item", (int)sub_5DCCA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_MyFaceStyle_Item", (int)sub_5DCEA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_MyHeadStyle_Item", (int)sub_5DD610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_MyHeadStyle", (int)sub_5DD990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_MyHeadStyle", (int)sub_5DD9F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_MyHairColor", (int)sub_5DD0A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_MyHairStyle", (int)sub_5DD170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_MyFaceStyle", (int)sub_5DD1C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_RectifyColor", (int)sub_5DE5C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_GetColorLumination", (int)sub_5DE7F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsCanDoAction", (int)sub_5DE4E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Check_StringCode", (int)sub_5DD580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_GXHHairStyle", (int)sub_5DD210, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_GXHFaceStyle", (int)sub_5DD2A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_GXHHeadStyle", (int)sub_5DD330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_GXHHairColor", (int)sub_5DD3C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_GXHHairColorCount", (int)sub_5DD530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_GXHHeadFrame", (int)sub_5DDA40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_MyHeadFrame_Item", (int)sub_5DDB10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_MyHeadFrame", (int)sub_5DDCE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetHeadFrameTimeFromTable", (int)sub_5DDD40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GemComposeLayedItem_Update", (int)sub_5DDED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GemMeltingLayedItem_Update", (int)sub_5DE0C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GemZhuoKeLayedItem_Update", (int)sub_5DE300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TargetFrame_Update_Name_Team", (int)sub_5DE980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TargetFrame_Update_HP_Team", (int)sub_5DE9D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TargetFrame_Update_MP_Team", (int)sub_5DEA30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TargetFrame_Update_Rage_Team", (int)sub_5DEA90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TargetFrame_Update_Eng_Team", (int)sub_5DEAF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TargetFrame_Update_Level_Team", (int)sub_5DEB50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TargetFrame_Update_Icon_Team", (int)sub_5DEBB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ToggleShowPetList", (int)sub_5DEC00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetNPCIDByServerID", (int)sub_5DEC50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetUIColor", (int)sub_5DECE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Challenge", (int)sub_5D65E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "MoneyChallenge", (int)sub_5D6680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "MoneyChallengeInvite2", (int)sub_5D6720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "MoneyChallengeAccept", (int)sub_5D67F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "MoneyChallengeClose", (int)sub_5D6880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "MoneyChallengeGetInfo", (int)sub_5D6960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IfHaveBuffByID", (int)sub_5D6AA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetBuffTimeByID", (int)sub_5D6B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetChallengeTeamMemberCount", (int)sub_5DEDD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetChallengeTeamMemberInfo", (int)sub_5DEE10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "RespondChallenge", (int)sub_5DEF60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMission_WhetherComplete", (int)sub_5DEFC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_ActivePos", (int)sub_5DF4F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPlayerMission_DelActivePos", (int)sub_5DF690, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetAutoSearch", (int)sub_5DF800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetAutoSearchSceneStartEnd", (int)sub_5DF970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetAutoSearchPriority", (int)sub_5DFAB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UpdateCaptchaData", (int)sub_5DFB80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SelCaptchaAnswer", (int)sub_5DFDC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLeftProtectTime", (int)sub_5DFFF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetDBLeftProtectTime", (int)sub_5DFFB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetForeverLock", (int)sub_5E0050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCurActiveRidePoint", (int)sub_5E0090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetCurActiveRidePoint", (int)sub_5E00D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetCanUseHotKey", (int)sub_5E0190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskCreateChar", (int)sub_5E01E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskAntiViolentCode", (int)sub_5E0CF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SendAntiViolentCode", (int)sub_5E0DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CloseSystemInfoWindow", (int)sub_5E0F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "DisconnectLoginServer", (int)sub_5E0F60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetProvincesNum", (int)sub_5E0FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "EnumProvinces", (int)sub_5E1040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "NumCityFromOneProvince", (int)sub_5E1280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCityNumFromOneProvinceId", (int)sub_5E11F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "getUINumbersFromIpRegion", (int)sub_5E13D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "StorPetsOneType", (int)sub_5E0260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "StorPetsOneType_Shop", (int)sub_5E02B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "PetsOneType_SetModel", (int)sub_5E0300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "PetsShopView_SetModel", (int)sub_5E03D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsZhuJiVipShopOpen", (int)sub_5E0390, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPetsOneTypeNum", (int)sub_5E0490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPetsShopPreViewNum", (int)sub_5E04D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "PetsOneType_GetAttr", (int)sub_5E0510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "PetsShopPreView_GetAttr", (int)sub_5E08C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsPetsOneType_HH", (int)sub_5E0CB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "PetShopView_ChangeAction", (int)sub_596790, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CreateActionItemForShow", (int)sub_59A3E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CreateActionItemForShowWithMaxNum", (int)sub_59A5B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ClearActionItemForShow", (int)sub_59A7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsPlayerQuickEnterPointTipShow", (int)sub_59A7D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetJieRiJiangLiInfo", (int)sub_59A9C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetNextJieRiJiangTip", (int)sub_59ABA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetJieRiJiangLiFlag", (int)sub_59AD00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetJieRiJiangLiFlag", (int)sub_59AD40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetPlayerAge", (int)sub_59ADA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetDailySeckillFlag", (int)sub_59ADF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetDailySeckillFlag", (int)sub_59AE30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetUpdateTipsFlag", (int)sub_59AE90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetUpdateTipsFlag", (int)sub_59AF20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "MengChongView_ChangeAction", (int)sub_5967F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "HuangLingView_ChangeAction", (int)sub_596850, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ShowQuickEnterPointTip", (int)sub_59A860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsRedPointInUIShow", (int)sub_59A930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetIsInSpringFlag", (int)sub_59AFC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetIsInSpringFlag", (int)sub_59B000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMsgNum", (int)sub_5E5F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMsgType", (int)sub_5E5F70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMsgIDByIndex", (int)sub_5E6260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMsgTimeTitle", (int)sub_5E60A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMsgPlayerGuild", (int)sub_5E6350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMsgDetail", (int)sub_5E64F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsMsgRead", (int)sub_5E67E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetMsgRead", (int)sub_5E68B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "HandleGameSetupAction", (int)sub_5E6950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetKfsData", (int)sub_5E69B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetKfsFixAttrEx", (int)sub_5E6DB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetKfsBase", (int)sub_5E6F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFixKfsBase", (int)sub_5E6FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetKfsSkill", (int)sub_5E70A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "KFS_UpdateKFSModel", (int)sub_5E7150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRMB_FaceInfo", (int)sub_5E7160, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UnInstallRMBFace", (int)sub_5E7550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRMB_FaceName", (int)sub_5E7340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRMB_FaceValidHour", (int)sub_5E7400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRMB_FaceRealID", (int)sub_5E7480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CheckRMBFace", (int)sub_5E7650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_RMB_ChatActionInfo", (int)sub_5E7790, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_RMB_ChatActionName", (int)sub_5E79D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_RMB_ChatActionValidHour", (int)sub_5E7A90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_RMB_ChatActionRealID", (int)sub_5E7B10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UnInstall_RMB_ChatAction", (int)sub_5E7BE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "UnInstall_RMB_ChatAction_BarItem", (int)sub_5E7D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Clear_ChatAction_Bar", (int)sub_5E7DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Set_RMB_ChatAction", (int)sub_5E7F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTeamBoardGoalNum", (int)sub_5E7FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "EnumTeamBoardGoal", (int)sub_5E8060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenDelCheckBox", (int)sub_5E8180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowMiniWatch", (int)sub_5E81F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowNormalWatch", (int)sub_5E8210, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ReConnect", (int)sub_5E8230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBugFBcount", (int)sub_5E84C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetBugFBcount", (int)sub_5E8500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CheckBugFBtime", (int)sub_5E8560, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ResetBugFBtime", (int)sub_5E85F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CheckCanSubmitBug", (int)sub_5E8610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SendBugFB", (int)sub_5E8650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSCMKillMonsterInfo", (int)sub_5CF840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSCMAlreadyKillNumber", (int)sub_5CF960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Open1On1Chat", (int)sub_5E88D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenGroupChat", (int)sub_5E8E60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SearchFriends", (int)sub_5E9060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSearchResultByIndex", (int)sub_5E91B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSearchResultByGUID", (int)sub_5E92E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSearchResultNum", (int)sub_5E9150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetImMsgNumber", (int)sub_5E9420, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenNotReadImMsg", (int)sub_5E9460, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CreateGroup", (int)sub_5E9480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetChatGroupNumber", (int)sub_5E9D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetChatGroupInfoByIndex", (int)sub_5E9DB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "DismissGroup", (int)sub_5E9BC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetChatGroupChiefIDByGroupID", (int)sub_5E9F60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "InviteFriendJoinGroup", (int)sub_5EA3C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GroupKickOut", (int)sub_5EA5B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ChangeGroupMaster", (int)sub_5EA7C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "QuitGroup", (int)sub_5EA9D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetIMGroupChatNumber", (int)sub_5EABA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetIMGroupChatData", (int)sub_5EAC30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetGroupUserNameByGuid", (int)sub_5EAE00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetUserNameByGuid", (int)sub_5EAF20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskSaleUserNotification", (int)sub_5EB000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AddSaleUserNotificationList", (int)sub_5EB1F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSaleUserNotification", (int)sub_5EB3C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSaleUserNumber", (int)sub_5EB370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetIMRecentByIndex", (int)sub_5EB570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetIMRecentByGUID", (int)sub_5EB6C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetGroupingName", (int)sub_5EB800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetGroupingNameByIndex", (int)sub_5EB890, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ModifyGroupingName", (int)sub_5EB980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ModifyIMStatus", (int)sub_5EBB80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMinWindowInfo", (int)sub_5EBC50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "PopMinWindow", (int)sub_5EBE90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "MuteGroup", (int)sub_5EC370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsChatGroupHaveMsg", (int)sub_5EA050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsGroupMute", (int)sub_5EC480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetIMIconNum", (int)sub_5EC520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCurDialogNpcId", (int)sub_5C8870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMySelfIMDress", (int)sub_5EC960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFriendIMDress", (int)sub_5ECAC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTujianBit", (int)sub_5ECEC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetTujianBit", (int)sub_5ECF40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTujianInfo_All", (int)sub_5ECFF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTujianInfo_Class", (int)sub_5ED220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTujianInfo_Taotu", (int)sub_5ED5A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTujianInfo_Card", (int)sub_5ED9A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetDirectory_TujianCard", (int)sub_5EE250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TujianBook_SetNPCModel", (int)sub_5EE380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowMengChong_SetNPCModel", (int)sub_5EE430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "MengChong_SetNPCModel", (int)sub_5EE850, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TujianCard_SetNPCModel", (int)sub_5EE930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TujianBook_SetHorseModel", (int)sub_5EE9E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TujianCard_SetHorseModel", (int)sub_5EEA90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TujianBook_SetDressModel", (int)sub_5EEB40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TujianCard_SetDressModel", (int)sub_5EEC20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowMengChongSelf_SetNPCModel", (int)sub_5EE4E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowMengChongOther_SetNPCModel", (int)sub_5EE590, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowMengChongPaint_SetNPCModel", (int)sub_5EE640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowMengChongGet1_SetNPCModel", (int)sub_5EE6F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ShowMengChongGet2_SetNPCModel", (int)sub_5EE7A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskandGetFriendIMDress", (int)sub_5ECCB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenModifyGroupNotice", (int)sub_5E8FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetChatGroupNotice", (int)sub_5EA0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetChatGroupName", (int)sub_5EA170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ModifyGroupNotice", (int)sub_5E9900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsChatGroupAllowMemberInvite", (int)sub_5EA1F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ChangeAllowMemberInvite", (int)sub_5EA280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetIMOnlinetimeTips", (int)sub_5EC6C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTrans", (int)sub_5EED00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetFriendPresent", (int)sub_5EED40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetServerName", (int)sub_5EF050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetSelfZoneWorldID", (int)sub_5EF0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetClanInviteInfo", (int)sub_5EF140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ClearClanInviteInfo", (int)sub_5EF220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetUnionInviteApplyInfo", (int)sub_5EF230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ClearUnionInviteApplyInfo", (int)sub_5EF2D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Change_MyFacePose", (int)sub_5EF2E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Get_MyFacePose", (int)sub_5EF3C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetGuildClanID", (int)sub_5EF480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetVipLevel", (int)sub_5EF510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetAccVipLevel", (int)sub_5EF550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetVipAccProgress", (int)sub_5EF590, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetVipProgress", (int)sub_5EF600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetVipInfoByIdx", (int)sub_5EF670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetVipFuncName", (int)sub_5EF780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetVipDressChest", (int)sub_5EF860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetvipInfoByVipID", (int)sub_5EF960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SendAskVipInfoMsg", (int)sub_5EFAF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMCardInfoByIdx", (int)sub_5EFBE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMCardInfoShowByIdx", (int)sub_5EFCC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetIsBaiBing", (int)sub_5EFDA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GMChat_OpenConnect", (int)sub_5EFDE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GMChat_Connect", (int)sub_5EFE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GMChat_ReConnect", (int)sub_5EFF60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GMChat_Cancel", (int)sub_5F0080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GMChat_ConfirmCancelConnect", (int)sub_5F0140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GMChat_MinConnectWnd", (int)sub_5F0310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GMChat_SendMsg", (int)sub_5F0350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GMChat_StopChat", (int)sub_5F07C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GMChat_ConfirmStopChat", (int)sub_5F08A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GMChat_MinChatWnd", (int)sub_5F09B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFormatTimeString", (int)sub_5F09F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCurrentServerTime", (int)sub_5D4E20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetServerDayTime", (int)sub_5D4E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetServerMinuteTime", (int)sub_5D4FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetDifDayWithServerTime", (int)sub_5D50F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateFYLBonusItem", (int)sub_5F0AB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateSafeScoreBonusItem", (int)sub_5F0C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateAnniversaryBonusItem", (int)sub_5F0CA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateQiankunBagItem", (int)sub_5F0D00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateShouKaiKaItem", (int)sub_5F0D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsHaveGot_FYL_BonusItem", (int)sub_5F0D40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsHaveGot_SafeScore_BonusItem", (int)sub_5F0DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetCYJAwardFlag", (int)sub_5F14C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateYuManQianKunBonusItem", (int)sub_5F0B10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateYuManQianKunSecondBonusItem", (int)sub_5F0B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateDiaoWenCCItem", (int)sub_5F0B50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateShuangXingDiaoWenItem", (int)sub_5F0BE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateOneDayGiftItem", (int)sub_5F0C00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateHuiGuiItem", (int)sub_5F0C20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsNewServerRHM", (int)sub_5F1500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetPowfixTime", (int)sub_5F0E00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetPowfixValue", (int)sub_5F0F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsSetPowfix", (int)sub_5F0FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_OnPowfixTime", (int)sub_5F1090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHMWeblink", (int)sub_5F11B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsMysteryShop", (int)sub_5F12F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_OnMSTime", (int)sub_5F13A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetBossRankTime", (int)sub_5F1C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_DoubleExpTime", (int)sub_5F1D90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetFubenRankTime", (int)sub_5F1AF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetFirstManTime", (int)sub_5F19A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetCostRankTime", (int)sub_5F17E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetLevelUpGiftTime", (int)sub_5F16D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHaoQingTime", (int)sub_5F1EA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetYuanBaoCostGiftTime", (int)sub_5F15C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLeftTimeToGetGiftsForCostYuanBao", (int)sub_5F2020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetBroadcastGiftTime", (int)sub_5F2270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetServerNewLotteryTime", (int)sub_5F2380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetServerNewFanLiMDEndTime", (int)sub_5F2490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetJinLiInfoByIndex", (int)sub_5F2550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetMSWebLink", (int)sub_5F26A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsSetPower", (int)sub_5F2900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_OnPowerTime", (int)sub_5F27E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetPowerValue", (int)sub_5F29C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetPowerTime", (int)sub_5F2A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsSetSuperGift", (int)sub_5F2B90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_OnSuperGiftTime", (int)sub_5F2C50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSuperGiftTime", (int)sub_5F2D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateActivityItemListForShow", (int)sub_5F2E80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateActivityItemListForCampaginShow", (int)sub_5F3030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "lua_GetClientVersionWebType", (int)sub_5F31C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetRoseTopListInfo", (int)sub_5F3390, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetYBTopListInfo", (int)sub_5F34A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetYBTopListWinerName", (int)sub_5F3640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetYBTopListInfo_tserver", (int)sub_5F36D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetYBNewSrvTopListInfo", (int)sub_5F3870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetYBNewSrvTopListWinerName", (int)sub_5F3A10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetYBNewSrvTopListState", (int)sub_5F3AA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetQixiSendTopListInfo", (int)sub_5F3BD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetQixiReceiveTopListInfo", (int)sub_5F3CC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetRoseSendTopListInfo", (int)sub_5F3DB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetRoseReceiveTopListInfo", (int)sub_5F3EA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearZhenYuanGiftActionItem", (int)sub_5F4500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetZhenYuanGiftActionItem", (int)sub_5F4520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateZhenYuanGiftActionItem", (int)sub_5F45E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearRongYaoActionItem", (int)sub_5F4600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetRongYaoActionItem", (int)sub_5F4620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateRongYaoActionItem", (int)sub_5F46E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearFaTieActionItem", (int)sub_5F4700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetFaTieActionItem", (int)sub_5F4720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateFaTieActionItem", (int)sub_5F47E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearBaoDian2ActionItem", (int)sub_5F4800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetBaoDian2ActionItem", (int)sub_5F4820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateBaoDian2ActionItem", (int)sub_5F48B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearAccLoginActionItem", (int)sub_5F48D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetAccLoginActionItem", (int)sub_5F48F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateAccLoginActionItem", (int)sub_5F49B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearZongziActionItem", (int)sub_5F4AB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetZongziActionItem", (int)sub_5F4AD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateZongziActionItem", (int)sub_5F4B60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearZhenYuanLiActionItem", (int)sub_5F4B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetZhenYuanLiActionItem", (int)sub_5F4BA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateZhenYuanLiActionItem", (int)sub_5F4C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearInfantCardGiftActionItem", (int)sub_5F49D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetInfantCardGiftActionItem", (int)sub_5F49F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateInfantCardGiftActionItem", (int)sub_5F4A90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearOldFriendGiftActionItem", (int)sub_5F51C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetOldFriendGiftActionItem", (int)sub_5F51E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateOldFriendGiftActionItem", (int)sub_5F52B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearOldFriendLotteryActionItem", (int)sub_5F52D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetOldFriendLotteryActionItem", (int)sub_5F52F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateOldFriendLotteryActionItem", (int)sub_5F53C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearMingDongDuiHuanActionItem", (int)sub_5F53E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetMingDongDuiHuanActionItem", (int)sub_5F5400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateMingDongDuiHuanActionItem", (int)sub_5F5490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearZiDianZengYingHaoActionItem", (int)sub_5F54B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetZiDianZengYingHaoActionItem", (int)sub_5F54D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateZiDianZengYingHaoActionItem", (int)sub_5F5560, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearSXKH_NixiActionItem", (int)sub_5F5580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetSXKH_NixiActionItem", (int)sub_5F55A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateSXKH_NixiActionItem", (int)sub_5F5630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearAnniversaryPreActionItem", (int)sub_5F4C50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetAnniversaryPreActionItem", (int)sub_5F4C70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateAnniversaryPreActionItem", (int)sub_5F4D30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearXiGuaShopActionItem", (int)sub_5F4D50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetXiGuaShopActionItem", (int)sub_5F4D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateXiGuaShopActionItem", (int)sub_5F4E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearCCShopActionItem", (int)sub_5F4E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetCCShopActionItem", (int)sub_5F4E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateCCShopActionItem", (int)sub_5F4F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetCCShopItemPro", (int)sub_5F4F50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearZhQiuRabbitActionItem", (int)sub_5F50C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetZhQiuRabbitActionItem", (int)sub_5F50E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateZhQiuRabbitActionItem", (int)sub_5F51A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearPhoneApproveActionItem", (int)sub_5F5650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetPhoneApproveActionItem", (int)sub_5F5670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdatePhoneApproveActionItem", (int)sub_5F5700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearGuiShiChanXiaoActionItem", (int)sub_5F5720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetGuiShiChanXiaoActionItem", (int)sub_5F5740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetGuiShiChanXiaoActionItemByItem", (int)sub_5F57D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateGuiShiChanXiaoActionItem", (int)sub_5F58C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearGuiShiChanXiaoZuoJiuListActionItem", (int)sub_5F58E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetGuiShiChanXiaoZuoJiuListActionItem", (int)sub_5F5900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateGuiShiChanXiaoZuoJiuListActionItem", (int)sub_5F59D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GuiShiGetStrangeObjCollection", (int)sub_5968B0, 0);
  sub_5F59F0(dword_D2DEF4);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMiJiSkillInfo", (int)sub_5F3200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsSuperman", (int)sub_5F3340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCurrentFreshManGuideItemValue", (int)sub_5F3B20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetCurrentFreshManGuideItemValue", (int)sub_5F3B70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipChangerate", (int)sub_5F3F90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetEquipTransferSP", (int)sub_5F4070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetEquipUpdatePro", (int)sub_5F40D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetEquipUpdateIsSetEquip", (int)sub_5F5C20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetRefluencePrivilegeFlag", (int)sub_5F7A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetRefluencePrivilegeData", (int)sub_5F7AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeFlag", (int)sub_5F7C70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeReturnTongBao", (int)sub_5F7CB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeLoginDayNum", (int)sub_5F7CF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeYuanBaoCost", (int)sub_5F7D30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeGift", (int)sub_5F7D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeItemName", (int)sub_5F7DF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeItemPrize", (int)sub_5F7E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeItemTimeCanBuy", (int)sub_5F7EF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeItemNumCanBuy", (int)sub_5F7F70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeItemTableIndex", (int)sub_5F7FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetRefluencePrivilegeItemLock", (int)sub_5F8070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeItemTableNum", (int)sub_5F8110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetOldFriendData", (int)sub_5F81E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetOldFriendData", (int)sub_5F8240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetRefluencePrivilegeLeftTime", (int)sub_5F8280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefluencePrivilegeLeftTime", (int)sub_5F82E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsInZYJTime", (int)sub_5F8660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsOnLaHuiLiuTime", (int)sub_5F8400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetRecoinNum", (int)sub_5F84B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSuperRecoinNum", (int)sub_5F8710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CreateAnniversaryPrizeItem", (int)sub_5F8320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ClearAnniversaryPrizeItem", (int)sub_5F83E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetRecoinEnumAttr", (int)sub_5F84F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSuperRecoinEnumAttr", (int)sub_5F8750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsHumanLearnedRlSkill", (int)sub_5F85E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetGemScore_FromGemTableIndex", (int)sub_5F8840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetDWScore_FromDiaoWenTableIndex", (int)sub_5F8960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipScore", (int)sub_596A60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipScoreSTL", (int)sub_597140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipTableValue", (int)sub_5973C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetPneumaScore", (int)sub_5974E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetFuTiSkillLevel", (int)sub_597770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsSelfEquipLocked", (int)sub_597900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetJingTongScore", (int)sub_5979C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetJingTongAttrInfo", (int)sub_5980A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLingPaiScore", (int)sub_598270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLingPaiInfo", (int)sub_598650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLingPaiBaoZhuIconName", (int)sub_598760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsSuperWeapon", (int)sub_598880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipQual", (int)sub_598A10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipAttrNum", (int)sub_598AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetEquipLevel", (int)sub_598960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetOtherFuTiSkillLevel", (int)sub_598B70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetOtherFuTiPetInfo", (int)sub_598D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SendZMXuanZhanMsg", (int)sub_5999E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SendAskAboutXZInfo", (int)sub_599D10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetLayNumByIndex", (int)sub_599DF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetItemNameByIndex", (int)sub_599EC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetItemIconNameByIndex", (int)sub_59A0B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetClientNpcIdByServerId", (int)sub_59A260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_InitZBVirtualItem", (int)sub_59A300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetEnchanceMinLevel", (int)sub_5F8A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetEnchanceSetInfo", (int)sub_5F8B10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetEnchanceSetNextLevel", (int)sub_5F8C80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetJinCanSi_Buy_Flag", (int)sub_59A340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_Haoqing_Prize_SetItem", (int)sub_5F9670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_TianXiaDiYi_Data", (int)sub_5F9440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_MenPaiDiYi_Data", (int)sub_5F9570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHXYEffect", (int)sub_5F9910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHXYLevel", (int)sub_5F97D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHXYUpgradeCost", (int)sub_5F9840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHXYGrade", (int)sub_5F9700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHXYExAttrInfo", (int)sub_5F9B90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHXYEffectRefixValue", (int)sub_5F9DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHXYExAttrRefixValue", (int)sub_5FA0C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsSetMemo", (int)sub_5FA260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SendBrotherRetSpirit", (int)sub_5FAA30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetQueryBrotherSpiritInfo", (int)sub_5FABA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetBinaryData", (int)sub_5FA2E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CreateMonthlySignItem", (int)sub_5FA380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ClearMonthlySignItem", (int)sub_5FA440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSelfLevelUp_EndTime", (int)sub_5FA460, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSelfLuckyDraw_EndTime", (int)sub_5FA4B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSelfSaveUp_EndTime", (int)sub_5FA500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSelfHeroBabBag_EndTime", (int)sub_5FA550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSelfDoubleExp_EndTime", (int)sub_5FA5A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSelfPowerFix_EndTime", (int)sub_5FA5F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetNewServerBroadcastInfo", (int)sub_5FA640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsopenServerBroadcastSwitch", (int)sub_5FA8D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetXinShouCarnButtonState", (int)sub_5FA990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetAnniversaryButtonState", (int)sub_5FAC40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearShituPlanActionItem", (int)sub_5FAD20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetShituPlanActionItem", (int)sub_5FAD40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateShituPlanActionItem", (int)sub_5FAE00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearShituGongfengActionItem", (int)sub_5FAE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetShituGongfengActionItem", (int)sub_5FAE40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateShituGongfengActionItem", (int)sub_5FAED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CreatePagodaHeroItem", (int)sub_5FAEF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ClearPagodaHeroItem", (int)sub_5FAFB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetEquipZhiZunNum", (int)sub_5F8DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetOtherEquipZhiZunNum", (int)sub_5F8E40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetEquipZhiZunExtend", (int)sub_5F8EC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetOtherEquipZhiZunExtend", (int)sub_5F8F40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetEquipZhiZunExtendLevel", (int)sub_5F8FC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetOtherEquipZhiZunExtendLevel", (int)sub_5F9040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetFiveElementsValueWithEquipAndJade", (int)sub_5F90C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetOtherFiveElementsValueWithEquipAndJade", (int)sub_5F9140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetFiveElementsValueWithJade", (int)sub_5F91C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetFiveElementsNextValueWithJade", (int)sub_5F9240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetFiveElementsBaseValue", (int)sub_5F92C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetFiveElementsNextBaseValue", (int)sub_5F9340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetOtherFiveElementsBaseValue", (int)sub_5F93C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateZhengZhaoData", (int)sub_5FAFD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetZhengZhaoData", (int)sub_5FB0C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetZhengZhaoNum", (int)sub_5FB080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearSanShenKeyActionItem", (int)sub_5FB340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetSanShenKeyActionItem", (int)sub_5FB360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateSanShenKeyActionItem", (int)sub_5FB3F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearHistoryConsumeRetActionItem", (int)sub_59B010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetHistoryConsumeRetActionItem", (int)sub_59B030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_UpdateHistoryConsumeRetActionItem", (int)sub_59B0C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CreateRecallPrizeItem", (int)sub_5FB410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "ClearRecallPrizeItem", (int)sub_5FB4D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetXiuChangRoomCount", (int)sub_5FB5D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetXiuChangRoomInfo", (int)sub_5FB610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetXiuChangSelectRoomInd", (int)sub_5FB700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetXiuChangSelectRoomInd", (int)sub_5FB750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_DressGemListA_Update", (int)sub_5FB820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_DressGemListB_Update", (int)sub_5FB980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetImpeachLeftSecond", (int)sub_5FBAE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetImpeachAllianceID", (int)sub_5FBB30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_AllianceScore", (int)sub_5FBE80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetImpeachQuality", (int)sub_5FBEE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetImeachRedInfo", (int)sub_5FBB80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetImpeachBlueInfo", (int)sub_5FBD00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetXiuChangUserRuleDes", (int)sub_5FB7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetItemClassByIndex", (int)sub_59B0E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetEquipPointByIndex", (int)sub_59B170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_CreateZZHKBonusItem", (int)sub_5FB4F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ClearZZHKBonusItem", (int)sub_5FB5B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHaoXiaRoad", (int)sub_5FBF40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetHaoXiaRoadFlag", (int)sub_5FBFE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetLastSkill_UI", (int)sub_5FC080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_AskServerNewLotteryNameList", (int)sub_5FC0D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_AskZhouNianYuanRankName", (int)sub_5FC200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetAnniversary7HIT", (int)sub_5FC170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_IsGameRunning", (int)sub_5FC2A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetChildrenDayScoreRank", (int)sub_5FC300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetChildrenDayScoreTop", (int)sub_5FC3C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetWatermelonScoreRank", (int)sub_5FC440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetWatermelonScoreTop", (int)sub_5FC500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ThanksgivingNum", (int)sub_5FC580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetThanksJackIndex", (int)sub_5FC640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ThanksShowInfo", (int)sub_5FC6B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ThanksJackpotTimes", (int)sub_5FC8F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_PreThanksJackpotTimes", (int)sub_5FCCD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ThanksRewardInfo", (int)sub_5FCE00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ThanksRewardID", (int)sub_5FCFC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ThanksJackRemainKind", (int)sub_5FD130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ThanksJackRemainInfo", (int)sub_5FD210, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ThanksgivingExNum", (int)sub_5FC5E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_ThanksExRewardList", (int)sub_5FD590, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetCookingNum", (int)sub_5FD8D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetTaotieNum", (int)sub_5FD910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_QingmingNum", (int)sub_5FD970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_QingmingExNum", (int)sub_5FD9B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetQingmingJackIndex", (int)sub_5FD9F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_QingmingShowInfo", (int)sub_5FDA60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_QingmingJackpotTimes", (int)sub_5FDCA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_PreQingmingJackpotTimes", (int)sub_5FE080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_QingmingRewardInfo", (int)sub_5FE1B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_QingmingRewardID", (int)sub_5FE370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_QingmingJackRemainKind", (int)sub_5FE4E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_QingmingJackRemainInfo", (int)sub_5FE5C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_QingmingExRewardList", (int)sub_5FE940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GenQRCode", (int)sub_5FEC80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetJiebanPartner", (int)sub_5FEEA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetJiebanHuiliuFlag", (int)sub_5FF070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetJiebanHuiliuFlag", (int)sub_5FF0D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSpringFestivalBiddingInfo", (int)sub_5FF110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetSpringFestivalBonusInfo", (int)sub_5FF310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetDuanWuBiddingBonusInfo", (int)sub_5FF630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXZNPCShopGoodsNum", (int)sub_5FF8B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXZNPCShopGoodsInfo", (int)sub_5FF940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXZNPCShopGoodsId", (int)sub_5FFCE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingJuanMaxCount", (int)sub_5FFD80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnInitXingJuanList", (int)sub_5FFE10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingJuanID", (int)sub_5FFF00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingJuanInfo", (int)sub_5FFF90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingJuanListCount", (int)sub_5FFEB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetActivedXingJuanID", (int)sub_6003E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetSkillCardMaxCount", (int)sub_600480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnInitSkillCardList", (int)sub_600510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetSkillCardListCount", (int)sub_600560, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetSkillCardID", (int)sub_6005B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetSkillCardInfo", (int)sub_600640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetActivedSkillCardID", (int)sub_6009D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingJuanLevelNeed", (int)sub_600A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingJuanOrderNeed", (int)sub_600BC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetSkillCardLevelNeed", (int)sub_600D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhenSlotAttr", (int)sub_600ED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhenSlotAttrListCount", (int)sub_600E80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingJuanAttr", (int)sub_601200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingJuanSlotAttr", (int)sub_601480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnSkillCardDesc", (int)sub_601700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnSkillCardExtraDesc", (int)sub_601A50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhenAllAttrDesc", (int)sub_601C50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetSkillCardRecycleInfo", (int)sub_601E20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnHaveXingJuanToSlot", (int)sub_602490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnHaveSkillCardToSlot", (int)sub_602530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnHaveNewXingJuan", (int)sub_6026E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnHaveNewSkillCard", (int)sub_602770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnHaveXingJuanToUpgrade", (int)sub_6027F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnHaveXingJuanToUnLock", (int)sub_6028F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnRemoveXingJuanNew", (int)sub_6029E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnRemoveSkillCardNew", (int)sub_602AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetOtherXingZhenSlotAttrListCount", (int)sub_602BE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetOtherXingZhenSlotAttr", (int)sub_602C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetOtherXingZhenAttr", (int)sub_602F60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetOtherXingZhenAttrListCount", (int)sub_603130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_InterestsInfo", (int)sub_603180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_YingXiongNum", (int)sub_603480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_YingXiongInfo", (int)sub_603510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_YingXiongAwardInfo", (int)sub_6038C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_YingXiongNextAwardLevel", (int)sub_603B60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_JiBanAwardNum", (int)sub_603CA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_JiBanAwardRange", (int)sub_603D30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_JiBanAwardInfo", (int)sub_603E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_InterestsLevelExp", (int)sub_604180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_YingXiongHaoganLevel", (int)sub_604250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_YingXiongAwardLevel", (int)sub_6042E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_InterestsGiveNum", (int)sub_604370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_InterestsTotalGiveNum", (int)sub_604400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_JiBanAwardFlag", (int)sub_604490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetXingZhen_JiBanTotalAttr", (int)sub_604520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetWLZDRankingListDataCount", (int)sub_59B240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetWLZDRankingListInfo", (int)sub_59B290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetMLZDRankingListMemberInfo", (int)sub_59B3C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetWLZDRankingListMyInfo", (int)sub_59B540, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnMyXingJuanID", (int)sub_601F70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnMySkillCardID", (int)sub_602010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnXingJuanCollection", (int)sub_6020B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnSkillCardCollection", (int)sub_602230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetSkillCardActiveHeroId", (int)sub_6023B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "LuaFnGetBaseShanHaiBi", (int)sub_604610, 0);
  v20 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v451, &unk_D2DEF0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v648, v20);
  LOBYTE(v660) = 19;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v648, (const struct LuaPlus::LuaObject *)dword_D2DEF4);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "DataPool", (struct LuaPlus::LuaObject *)&v648);
  v21 = operator new(0x18u);
  v465 = v21;
  LOBYTE(v660) = 20;
  if ( v21 )
    v22 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v21);
  else
    v22 = 0;
  dword_D2DCC8 = v22;
  LOBYTE(v660) = 19;
  v23 = LuaPlus::LuaObject::CreateTable(&v659, &v544, "AbilityTeacherTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DCC8, v23);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v544);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DCC8,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DCC8);
  sub_877220((LuaPlus::LuaObject *)dword_D2DCC8, "IsPresent", (int)sub_59D740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DCC8, "GetAbilityID", (int)sub_59D7A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DCC8, "GetNeedExp", (int)sub_59D7E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DCC8, "GetNeedMoney", (int)sub_59D820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DCC8, "GetNeedSkillExp", (int)sub_59D940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DCC8, "GetNeedLevel", (int)sub_59D980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DCC8, "GetServerData", (int)sub_59D9C0, 0);
  v24 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v456, &unk_D2DCC4);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v564, v24);
  LOBYTE(v660) = 21;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v564, (const struct LuaPlus::LuaObject *)dword_D2DCC8);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "AbilityTeacher", (struct LuaPlus::LuaObject *)&v564);
  v25 = operator new(0x18u);
  v465 = v25;
  LOBYTE(v660) = 22;
  if ( v25 )
    v26 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v25);
  else
    v26 = 0;
  dword_D31BBC = v26;
  LOBYTE(v660) = 21;
  v27 = LuaPlus::LuaObject::CreateTable(&v659, &v485, "PetTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31BBC, v27);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v485);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31BBC,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31BBC);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "IsPresent_PetBank", (int)sub_64AE70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPet_Count_PetBank", (int)sub_64AF60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetFirstPetPosInBank_PetBank", (int)sub_64BE70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetIndexByGUID_PetBank", (int)sub_64AFA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetGUIDByIndex_PetBank", (int)sub_64B050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetList_Appoint_PetBank", (int)sub_64B140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetJYSLPetList_Appoint_PetBank", (int)sub_64B320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetJYSLPetRemainTime", (int)sub_64B510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetModel_PetBank", (int)sub_64B760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetModel_JYSLPetBank", (int)sub_64B800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SavePetIntoBank_PetBank", (int)sub_64B8A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ShowTargetPet_PetBank", (int)sub_64BDD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PetBank_PetListSelectChange", (int)sub_64BF70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PetBank_WriteLog", (int)sub_64C020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ShowListTargetPet_PetBank", (int)sub_64C200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetCurrentSelectPet_PetBank", (int)sub_64C2B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetCurrentSelectPet_PetBank", (int)sub_64C310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ShowBagSelectPet_PetBank", (int)sub_64C350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetFirstPetPosInPag", (int)sub_64C3F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetPossModelTypeById", (int)sub_64C430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetPossModelNameById", (int)sub_64C510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetPossIsBroadcastById", (int)sub_64C5E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_IsPetMasterEffectActive", (int)sub_64C6C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPetMasterTotalEffect", (int)sub_64C7D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetMasterTotalEffectValue", (int)sub_64C8E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetHuanlingModelID", (int)sub_64D2B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetHuanlingPortraitByIndex", (int)sub_64D370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetHuanlingIdByIndex", (int)sub_64DA30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetQuality", (int)sub_64DAF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetHuanlingID", (int)sub_646940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetQuality", (int)sub_6469F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "IsPresent", (int)sub_63CE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPet_Count", (int)sub_63CF00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetIndexByGUID", (int)sub_63CF40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetList_Appoint", (int)sub_63CFF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Go_Fight", (int)sub_63D1E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Go_Relax", (int)sub_63D460, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Go_Free", (int)sub_63D900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PossessionPet", (int)sub_63D570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "RestorePet", (int)sub_63D7F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Feed", (int)sub_63DC70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Dome", (int)sub_63DE40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "IsProtect", (int)sub_63E010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetGrowRate4", (int)sub_63E0C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetFuTiPetIndex", (int)sub_59B5D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetTypeName", (int)sub_63E130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetName", (int)sub_63E2E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetID", (int)sub_63E400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetNaturalLife", (int)sub_63E680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetMaxLife", (int)sub_63E730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetHappy", (int)sub_63EAF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetConsort", (int)sub_63E520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetSex", (int)sub_63E5E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetBasic", (int)sub_640150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetLoyalgGade", (int)sub_63E830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetLevel", (int)sub_63E8E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPromoteLevel_PetBank", (int)sub_63EF10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetLastProcreateLevel", (int)sub_63E990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetType", (int)sub_63EA40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetHP", (int)sub_63F150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetMaxHP", (int)sub_63F200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetMP", (int)sub_63F2B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetMaxMP", (int)sub_63F350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetStrAptitude", (int)sub_63EBA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPFAptitude", (int)sub_63EC50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetDexAptitude", (int)sub_63ED00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetIntAptitude", (int)sub_63EDB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetStaAptitude", (int)sub_63EE60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetStr", (int)sub_63F400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetInt", (int)sub_63F4B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetDex", (int)sub_63F560, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPF", (int)sub_63F610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetSta", (int)sub_63F6C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetJinJieGradeAndLevel_PetBank", (int)sub_63F770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetJinJieGrade", (int)sub_63F860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetJinJieLvl", (int)sub_63F910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetCanBeJinJieInfo", (int)sub_63F9C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetAllPetTakeLevelByGUID", (int)sub_63FCC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetJinJieStr", (int)sub_63FDE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetJinJieSpr", (int)sub_63FE90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetJinJieCon", (int)sub_63FF40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetJinJieINT", (int)sub_63FFF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetJinJieDex", (int)sub_6400A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPotential", (int)sub_640200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetExp", (int)sub_6402B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPhysicsAttack", (int)sub_6403F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetMagicAttack", (int)sub_6404A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPhysicsRecovery", (int)sub_640550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetMagicRecovery", (int)sub_640600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetMiss", (int)sub_6406B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetShootProbability", (int)sub_640760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Add_Attribute", (int)sub_640810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Change_Name", (int)sub_640A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetIsFighting", (int)sub_640D80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetIsPossession", (int)sub_640E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetModel", (int)sub_640F20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetHeadModel", (int)sub_640FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPetRhdPossModel", (int)sub_641040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPetPossVisual", (int)sub_6410D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPetPossVisualByFitValue", (int)sub_641130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPetPossColorRateByFitValue", (int)sub_6411C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPetPossColorRate", (int)sub_641250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ClearUpPetPossColorRate", (int)sub_6412B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPetPossColorHY", (int)sub_6412C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Pet_B", (int)sub_641320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ClearUpPetPossColorHY", (int)sub_641330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPetJianColorRateByFitValue", (int)sub_641340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ClearUpPetJianColorRate", (int)sub_6413D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetGXHColorRateByFitValue", (int)sub_6413E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ClearUpGXHColorRate", (int)sub_641470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetPossModel", (int)sub_641480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PetOpenPossJian", (int)sub_6414C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PetOpenHuanSeJian", (int)sub_641540, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPetRhdPossVisual", (int)sub_641600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetCriticalAttack", (int)sub_641680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetCriticalDefence", (int)sub_641730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetSkillLevelupModel", (int)sub_6417E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetSkillIDbyIndex", (int)sub_641870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetSkillStudyModel", (int)sub_641950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ShowTargetPet", (int)sub_6419E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SkillStudy_Do", (int)sub_641A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SkillStudyUnlock", (int)sub_641E90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SkillStudy_MenPaiSkill_Created", (int)sub_641F60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SkillStudy_MenPaiSkill_Clear", (int)sub_642000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetGUID", (int)sub_642020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ShowPetList", (int)sub_6420F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetYuanbaoBuyState", (int)sub_642180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetYuanbaoBuyState", (int)sub_642210, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetFightPetAsMainTarget", (int)sub_6422A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ShowMyPetContexMenu", (int)sub_642330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "HandlePetMenuItem", (int)sub_642540, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "HandlePetMenuItemSelf", (int)sub_6429A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetBankPortraitByIndex", (int)sub_642CF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetPortraitByIndex", (int)sub_642DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetImpactNum", (int)sub_642EB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetImpactIconNameByIndex", (int)sub_642F70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "CheckRClick", (int)sub_6430B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "EnumPetSkill", (int)sub_643280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Select_Pet", (int)sub_643420, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetAIType", (int)sub_6434C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetAIType_PetBank", (int)sub_643570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetSkillPassive", (int)sub_643610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Free_Confirm", (int)sub_6436F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetFoodType", (int)sub_643950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPetLocation", (int)sub_643A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetLocation", (int)sub_643AA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "LockPetProcreate", (int)sub_643C60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ConfirmPetProcreate", (int)sub_643B50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PetProcreate_Clear", (int)sub_643D30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ViewPetDetailData", (int)sub_643D50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetProcreate_Other_Model", (int)sub_643EB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetProcreate_Self_Model", (int)sub_643EF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetGrowLevel", (int)sub_643190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetTakeLevel", (int)sub_643F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetAttackTrait", (int)sub_643FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetAttackTraitID", (int)sub_6440D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetSavvy", (int)sub_644180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetFitValue", (int)sub_644230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetGrowRate", (int)sub_6442E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetAIType", (int)sub_6443A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetHappy", (int)sub_644450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetType", (int)sub_644500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetNaturalLife", (int)sub_6445B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetMaxLife", (int)sub_644660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetLoyalgGade", (int)sub_644760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetHP", (int)sub_644810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetMP", (int)sub_6448C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetMaxHP", (int)sub_644960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetMaxMP", (int)sub_644A10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetStrAptitude", (int)sub_644AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPFAptitude", (int)sub_644B70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetDexAptitude", (int)sub_644C20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetIntAptitude", (int)sub_644CD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetStaAptitude", (int)sub_644D80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetStr", (int)sub_644E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetInt", (int)sub_644EE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetDex", (int)sub_644F90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPF", (int)sub_645040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetSta", (int)sub_6450F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetBasic", (int)sub_6451A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPotential", (int)sub_645250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetExp", (int)sub_645300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPhysicsAttack", (int)sub_645440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetMagicAttack", (int)sub_6454F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPhysicsRecovery", (int)sub_6455A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetMagicRecovery", (int)sub_645650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetShootProbability", (int)sub_645700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetMiss", (int)sub_6457B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_SetModel", (int)sub_645860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetConsort", (int)sub_6458F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetGoodsProtect_Pet", (int)sub_6459B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetID", (int)sub_645A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetLevel", (int)sub_645B90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetName", (int)sub_645C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPet_Count", (int)sub_645D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPetIndexByGUID", (int)sub_645DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPetTypeName", (int)sub_645E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetSex", (int)sub_646000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_IsPresent", (int)sub_6460A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetTakeLevel", (int)sub_646180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetAttackTrait", (int)sub_646200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetSavvy", (int)sub_646330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetFitValue", (int)sub_6463E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPetList_Appoint", (int)sub_646490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetCriticalAttack", (int)sub_646710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetCriticalDefence", (int)sub_646660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetFoodType", (int)sub_6467C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPetTypeName", (int)sub_645E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetGrowRate", (int)sub_646880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPetGrowLevel", (int)sub_646A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetPercent_Lx", (int)sub_64A740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetAttackCold", (int)sub_646E20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetAttackFire", (int)sub_646ED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetAttackLight", (int)sub_646F80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetAttackPoison", (int)sub_647030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetDefenceCold", (int)sub_6470E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetDefenceFire", (int)sub_647190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetDefenceLight", (int)sub_647240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetDefencePoison", (int)sub_6472F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetResistCold", (int)sub_6473A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetResistFire", (int)sub_647450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetResistLight", (int)sub_647500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetResistPoison", (int)sub_6475B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetJinJieGrade", (int)sub_647660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetJinJieLvl", (int)sub_647710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetJinJieStr", (int)sub_6477C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetJinJieSpr", (int)sub_647870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetJinJieCon", (int)sub_647920, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetJinJieINT", (int)sub_6479D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetJinJieDex", (int)sub_647A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetFightAction", (int)sub_647B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetSelectPetIdx", (int)sub_647C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetRelaxAction", (int)sub_647CC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetPossessionAction", (int)sub_647DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetRestoreAction", (int)sub_647EE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetCanFanzhiPet", (int)sub_647FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "EnumTitleByIdx", (int)sub_648040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetTitleNum", (int)sub_648300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetCurrentTitle", (int)sub_6483C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PetAskChangeCurrentTitle", (int)sub_648660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PetOpenTitleList", (int)sub_648AF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetNullCurTitle", (int)sub_6487A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "NotifySelChange", (int)sub_648B70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "NotifyPetDlgClosed", (int)sub_648BE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "EnumPetSkillBarItem", (int)sub_648C00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetSkillBarItemCount", (int)sub_648D40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PetOpenPetJian", (int)sub_6488C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "AnniversaryOpenPetJian", (int)sub_648A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "CheckPetSkillStudyMoreMoneyMode", (int)sub_648D80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "OpenPetSkillStudyMsgBox", (int)sub_648F40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ClosePetSkillStudyMsgBox", (int)sub_648F60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ConfirmPetSkillStudy", (int)sub_648F80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetSkillLevelupInfo", (int)sub_6495F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "UpdateProductAction", (int)sub_59B610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetSkillName", (int)sub_59B850, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetPetMedicineHC", (int)sub_6497D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_OneKeyUnEquip", (int)sub_649970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "IsPetHaveEquip", (int)sub_649C00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetData", (int)sub_649CA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PetToShelizi", (int)sub_648FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "ClearSheliziPet", (int)sub_6493F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetDBCName", (int)sub_649410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetStudyNewSkillModel", (int)sub_6498E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPropagateModel", (int)sub_649F90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "EnableHuanhua", (int)sub_64A110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetHuanhuaMoney", (int)sub_64A210, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetRate_LxUp", (int)sub_64A320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPercent_LxUp", (int)sub_64A480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPercent_Lx", (int)sub_64A5E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetLixing", (int)sub_64A8A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetGeneration", (int)sub_64A960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetLixing", (int)sub_646B60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_GetGeneration", (int)sub_646C20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "PetHHComfirm", (int)sub_646CD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetHHPetOriDataId", (int)sub_64AA10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetDataID", (int)sub_64ABA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Other_SetSelectedIdx", (int)sub_646DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "UpdatePetList", (int)sub_64AC50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SethuantongModel", (int)sub_64A020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "SetPetForZNQModel", (int)sub_64A0B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetPetType", (int)sub_64AC70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "CloseTeamPetProCreate", (int)sub_64AD20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "CloseSignalPetProCreate", (int)sub_64AD40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "IsFreeing", (int)sub_64AD60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "GetIsBaiShou", (int)sub_64AE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_GetPetVarLevel", (int)sub_64C9F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_IsEnableLianHua", (int)sub_64CB20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_LianHuaConfirm", (int)sub_64CD40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_LianHuaConfirmRet", (int)sub_64CDB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_GetLianHuaProduct", (int)sub_64CDD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_GetPetHuanLingIdByItem", (int)sub_64CEE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_GetPetHuanLingInfo", (int)sub_64CFC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_InitPetHuanLingList", (int)sub_64D460, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_GetHuanLingListCount", (int)sub_64D4C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_GetPetHuanLingInfoFromList", (int)sub_64D510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_UpdatePetHuanLingModel", (int)sub_64D810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_UpdateShopPetHuanLingModel", (int)sub_64D8C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_IsHavePetHuanLingCollection", (int)sub_64D970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_OpenPetHuanLingUI", (int)sub_64DA10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_IsHuanLingInUse", (int)sub_64DC00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_NianShouNingYuConfirm", (int)sub_64DCD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_UpdateNianShouHuanYuModel", (int)sub_64DD40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_UpdateNianShouHuanYuPreviewModel", (int)sub_64DDF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_NianShouHuanYuPreviewModel_ChangeAction", (int)sub_64DEA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_NianShouHuanYuRareConfirm", (int)sub_64DF00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_NianShouHuanYuBindConfirm", (int)sub_64DF70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_NianShouHuanYuRareConfirmed", (int)sub_64DF90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_NianShouHuanYuBindConfirmed", (int)sub_64DFB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_OpenNianShouHuanYuJian", (int)sub_64DFD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_NianShouHuanYuUpBindConfirm", (int)sub_64E030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_NianShouHuanYuUpBindConfirmed", (int)sub_64E050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_GetLianHuaNeedGrowLevel", (int)sub_64CC30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31BBC, "Lua_PetChangemodelConfirm", (int)sub_64E070, 0);
  v28 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v386, &unk_C6B4DC);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v566, v28);
  LOBYTE(v660) = 23;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v566, (const struct LuaPlus::LuaObject *)dword_D31BBC);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Pet", (struct LuaPlus::LuaObject *)&v566);
  v29 = operator new(0x18u);
  v465 = v29;
  LOBYTE(v660) = 24;
  if ( v29 )
    v30 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v29);
  else
    v30 = 0;
  dword_D35A8C = v30;
  LOBYTE(v660) = 23;
  v31 = LuaPlus::LuaObject::CreateTable(&v659, &v542, "PetInviteFriendTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D35A8C, v31);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v542);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D35A8C,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D35A8C);
  sub_877220((LuaPlus::LuaObject *)dword_D35A8C, "GetInviteNum", (int)sub_6D4630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A8C, "GetHumanINFO", (int)sub_6D48E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A8C, "GetInviteMsg", (int)sub_6D4B70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A8C, "SetPetModel", (int)sub_6D4C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A8C, "ShowTargetPet", (int)sub_6D4CD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A8C, "GetPetINFO", (int)sub_6D4DB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A8C, "SendAuditMsg", (int)sub_6D5130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A8C, "ShowPetFriends", (int)sub_6D5230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A8C, "ShowSearchPage", (int)sub_6D5390, 0);
  v32 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v448, &off_C73DDC);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v568, v32);
  LOBYTE(v660) = 25;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v568, (const struct LuaPlus::LuaObject *)dword_D35A8C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "PetInviteFriend", (struct LuaPlus::LuaObject *)&v568);
  v33 = operator new(0x18u);
  v465 = v33;
  LOBYTE(v660) = 26;
  if ( v33 )
    v34 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v33);
  else
    v34 = 0;
  dword_D2D678 = v34;
  LOBYTE(v660) = 25;
  v35 = LuaPlus::LuaObject::CreateTable(&v659, &v503, "FindFriendDataPool", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2D678, v35);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v503);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2D678,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2D678);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetSimpleInfoNum", (int)sub_51E350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetSimpleInfoNum", (int)sub_51E3A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetSimpleInfoByPos", (int)sub_51E3F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetSimpleVoteInfoByPos", (int)sub_51E5A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "CleanSearchRetInfo", (int)sub_51EBE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetDetailInfo", (int)sub_51E750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "CleanSearchRetInfo", (int)sub_51EBE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetSearchRetInfoNum", (int)sub_51EC00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetSearchRetInfoByPos", (int)sub_51EC50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetVoteInfoNum", (int)sub_51EE10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetVoteInfoByPos", (int)sub_51EE60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "ContexMenuForVoteInfo", (int)sub_51EFB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "ContexMenuPingbiOrTousu", (int)sub_51F240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetTickCount", (int)sub_51F3C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetPlayerBBSAdGUID", (int)sub_51F400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetPlayerBBSAdType", (int)sub_51F490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetPlayerBBSADTitle", (int)sub_51F4D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "GetPlayerMsgNum", (int)sub_51F510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "EnumPlayerMsg", (int)sub_51F550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "AddPlayerMsg", (int)sub_51F680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "ClearPlayerMsg", (int)sub_51FB70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D678, "SetADTitle", (int)sub_51FC70, 0);
  v36 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v384, &unk_D2D680);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v570, v36);
  LOBYTE(v660) = 27;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v570, (const struct LuaPlus::LuaObject *)dword_D2D678);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "FindFriendDataPool", (struct LuaPlus::LuaObject *)&v570);
  v37 = operator new(0x18u);
  v465 = v37;
  LOBYTE(v660) = 28;
  if ( v37 )
    v38 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v37);
  else
    v38 = 0;
  dword_D31EB4 = v38;
  LOBYTE(v660) = 27;
  v39 = LuaPlus::LuaObject::CreateTable(&v659, &v540, "TargetPetTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31EB4, v39);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v540);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31EB4,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31EB4);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "IsPresent", (int)sub_66E740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPetType", (int)sub_66E7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPetTypeName", (int)sub_66E810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetName", (int)sub_66E970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetIsBaiShou", (int)sub_66EA40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetID", (int)sub_66EAB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetNaturalLife", (int)sub_66ECF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetMaxLife", (int)sub_66ED50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetHappy", (int)sub_66EF10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetConsort", (int)sub_66EBA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetGoodsProtect_Pet", (int)sub_66EC30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetSex", (int)sub_66ECA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetBasic", (int)sub_66F750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetLoyalgGade", (int)sub_66ED90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetLevel", (int)sub_66EDF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetLastProcreateLevel", (int)sub_66EE50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetType", (int)sub_66EEB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetHP", (int)sub_66F150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetMaxHP", (int)sub_66F1B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetMP", (int)sub_66F210, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetMaxMP", (int)sub_66F270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetStrAptitude", (int)sub_66EF70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPFAptitude", (int)sub_66EFD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetDexAptitude", (int)sub_66F030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetIntAptitude", (int)sub_66F090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetStaAptitude", (int)sub_66F0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetStr", (int)sub_66F2D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetInt", (int)sub_66F330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetDex", (int)sub_66F390, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPF", (int)sub_66F3F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetSta", (int)sub_66F450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetJinJieGrade", (int)sub_66F4B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetJinJieLvl", (int)sub_66F510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetJinJieStr", (int)sub_66F570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetJinJieSpr", (int)sub_66F5D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetJinJieCon", (int)sub_66F630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetJinJieINT", (int)sub_66F690, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetJinJieDex", (int)sub_66F6F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPotential", (int)sub_66F7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetExp", (int)sub_66F810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPhysicsAttack", (int)sub_66F870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetMagicAttack", (int)sub_66F8D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPhysicsRecovery", (int)sub_66F930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetMagicRecovery", (int)sub_66F990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetMiss", (int)sub_66F9F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetShootProbability", (int)sub_66FA50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetIsFighting", (int)sub_66FAB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "SetModel", (int)sub_66FB30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "SetModel2", (int)sub_66FBB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "SetModelAboutHuanLing", (int)sub_66FB70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "CopyMyPet", (int)sub_66FBF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetCriticalAttack", (int)sub_66FC70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetCriticalDefence", (int)sub_66FCD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetAIType", (int)sub_66FD30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetFoodType", (int)sub_66FD90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetTakeLevel", (int)sub_66FDF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetAttackTrait", (int)sub_66FE50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetSavvy", (int)sub_66FF30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetFitValue", (int)sub_66FF90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetGrowRate", (int)sub_66FFF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPetGrowLevel", (int)sub_670060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetAttackCold", (int)sub_670100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetAttackFire", (int)sub_670170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetAttackLight", (int)sub_6701E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetAttackPoison", (int)sub_670250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetDefenceCold", (int)sub_6702C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetDefenceFire", (int)sub_670330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetDefenceLight", (int)sub_6703A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetDefencePoison", (int)sub_670410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetResistCold", (int)sub_670480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetResistFire", (int)sub_6704F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetResistLight", (int)sub_670560, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetResistPoison", (int)sub_6705D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetLixing", (int)sub_670640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetGeneration", (int)sub_6706B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPercent_Lx", (int)sub_670710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "IsPetMasterEffectActive", (int)sub_670810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPetMasterTotalEffect", (int)sub_6708E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPetHuanlingID", (int)sub_6709A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EB4, "GetPetQuality", (int)sub_670A00, 0);
  v40 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v446, &unk_D31EB0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v572, v40);
  LOBYTE(v660) = 29;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v572, (const struct LuaPlus::LuaObject *)dword_D31EB4);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "TargetPet", (struct LuaPlus::LuaObject *)&v572);
  v41 = operator new(0x18u);
  v465 = v41;
  LOBYTE(v660) = 30;
  if ( v41 )
    v42 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v41);
  else
    v42 = 0;
  dword_D2DD14 = v42;
  LOBYTE(v660) = 29;
  v43 = LuaPlus::LuaObject::CreateTable(&v659, &v475, "BankTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DD14, v43);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v475);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DD14,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DD14);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "IsPresent", (int)sub_5A0F70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "OpenSaveFrame", (int)sub_5A0FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "OpenGetFrame", (int)sub_5A1000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetInputMoney", (int)sub_5A1060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "SaveMoneyToBank", (int)sub_5A1330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetMoneyFromBank", (int)sub_5A14B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetBankMoney", (int)sub_5A1650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "MoveItemToPacket", (int)sub_5A1780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetRentBoxNum", (int)sub_5A1840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetRentBoxInfo", (int)sub_5A18D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "SetCurRentIndex", (int)sub_5A1A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "TransformCoin", (int)sub_5A1A50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "Close", (int)sub_5A1B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "EnumItem", (int)sub_5A1BD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetNpcId", (int)sub_5A1D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetBagMoney", (int)sub_5A1DB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "PackUpBank", (int)sub_5A1F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "SetOpenWhichBank", (int)sub_5A26C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetAccess", (int)sub_5A27A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "AskTemBankList", (int)sub_5A2850, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "EnumTemItem", (int)sub_5A2930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "TemBankPackUp", (int)sub_5A2AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "CleanAllItemInTemBank", (int)sub_5A2FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetTemBankItemNum", (int)sub_5A3070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetTemBankSpace", (int)sub_5A30D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "CheckIsInTServer", (int)sub_5A3130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "MoveAllTemBankItemToPacket", (int)sub_5A3180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "LockTemBankItem", (int)sub_5A3200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetUnlockTemBankItemCount", (int)sub_5A32C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "IsTemBankHaveEmptyPos", (int)sub_5A3380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "Lua_GetItemAttachParam", (int)sub_5A33E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD14, "GetTemBankItemBindStatus", (int)sub_5A34E0, 0);
  v44 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v404, &unk_D2DD10);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v574, v44);
  LOBYTE(v660) = 31;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v574, (const struct LuaPlus::LuaObject *)dword_D2DD14);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Bank", (struct LuaPlus::LuaObject *)&v574);
  v45 = operator new(0x18u);
  v465 = v45;
  LOBYTE(v660) = 32;
  if ( v45 )
    v46 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v45);
  else
    v46 = 0;
  dword_D2E1EC = v46;
  LOBYTE(v660) = 31;
  v47 = LuaPlus::LuaObject::CreateTable(&v659, &v538, "ExchangeTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2E1EC, v47);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v538);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2E1EC,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2E1EC);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "IsPresent", (int)sub_605F40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "SendExchangeApply", (int)sub_605FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "OpenExchangeFrame", (int)sub_606430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "GetItemNum", (int)sub_606800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "GetItemAction", (int)sub_6069B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "GetMoney", (int)sub_6069C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "LockExchange", (int)sub_606C20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "IsLocked", (int)sub_606D00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "AcceptExchange", (int)sub_606E80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "ExchangeCancel", (int)sub_606FE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "OpenPetFrame", (int)sub_6070A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "GetMoneyFromInput", (int)sub_607270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "IsStillAnyAppInList", (int)sub_607530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "GetOthersName", (int)sub_607570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "GetOthersGUID", (int)sub_607760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "AddPet", (int)sub_6078F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "GetPetNum", (int)sub_608630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "EnumPet", (int)sub_608780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "DelSelectPet", (int)sub_608950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "ViewPetDesc", (int)sub_608A50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "BeForbidden", (int)sub_608C20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "IsSendSelfToDest", (int)sub_608D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "SendExchangeCheckCode", (int)sub_608DF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "AskExchangeCheckCode", (int)sub_608FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "SendEnableAcceptBtn", (int)sub_609140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "CloseExchangeInfo", (int)sub_609180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E1EC, "GetTickCount", (int)sub_608BE0, 0);
  v48 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v444, &unk_D2E1E8);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v576, v48);
  LOBYTE(v660) = 33;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v576, (const struct LuaPlus::LuaObject *)dword_D2E1EC);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Exchange", (struct LuaPlus::LuaObject *)&v576);
  v49 = operator new(0x18u);
  v465 = v49;
  LOBYTE(v660) = 34;
  if ( v49 )
    v50 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v49);
  else
    v50 = 0;
  dword_D31960 = v50;
  LOBYTE(v660) = 33;
  v51 = LuaPlus::LuaObject::CreateTable(&v659, &v501, "LifeAbilityTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31960, v51);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v501);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31960,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31960);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetLifeAbility_Number", (int)sub_61E480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescr_Material_Number", (int)sub_61E520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescr_Material", (int)sub_61E5E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescr_Material_Tooltip", (int)sub_61E680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescrList_Item_FromNum", (int)sub_61E7A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescr_Item_Maximum", (int)sub_61E880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescr_Item_IsNeedSpecial", (int)sub_61EB80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescr_Material_Hold_Count", (int)sub_61EC10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Update_Synthesize", (int)sub_61ED30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Open_Compose_Gem_Page", (int)sub_61ED90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Do_Enchase", (int)sub_61EE00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Do_Enchase_Four", (int)sub_61EF40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "ClearSlotFour", (int)sub_61F2F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Is_SlotFour", (int)sub_61F080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Do_Combine", (int)sub_61F370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Do_Gem_Change", (int)sub_61F830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquip_Gem", (int)sub_61FB00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquip_GemLevel", (int)sub_61FBC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquip_HoleCount", (int)sub_620010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquip_GemCount", (int)sub_620530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquip_GemTypeSubindex", (int)sub_61FCA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquip_GemID", (int)sub_61FDC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetGemLevelupTBInfo", (int)sub_61FE90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Enchase_Preparation", (int)sub_6209D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Compound_Preparation", (int)sub_620B50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Can_Enchase", (int)sub_620670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Can_Combine", (int)sub_620870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Lock_Packet_Item", (int)sub_620CB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Lock_Packet_ItemByID", (int)sub_620D80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescr_Explain", (int)sub_620E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetNpcId", (int)sub_620F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Test_Prescr_Item", (int)sub_620F70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescr_Material_Consume", (int)sub_6211C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescr_Consume_Vigor_Energy", (int)sub_621290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Do_SeparateGem", (int)sub_621450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescr_Consume_ContriAttr", (int)sub_621380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetPrescription_Kind", (int)sub_621610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetItem_Class", (int)sub_6216E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Stiletto_Preparation", (int)sub_621770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetSplitGem_Gem", (int)sub_621AD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetSplitGem_GemEx", (int)sub_622080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "SplitGem_Update", (int)sub_6223B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Baoshiyi_Gem", (int)sub_623320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Baoshiyi_SetGemByIndex", (int)sub_6234D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Baoshiyi_Update", (int)sub_6233D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Do_Displace", (int)sub_623680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Baoshiyi_GetGemType", (int)sub_623790, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetQuestUI_Demand", (int)sub_623870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetQuestUI_Reward", (int)sub_623900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Equip_TableIndex", (int)sub_623B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Equip_VisualID", (int)sub_623990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Wear_Equip_VisualID", (int)sub_623C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "SetSuperWeapon9NewModel", (int)sub_623D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Equip_Level", (int)sub_623DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Equip_Point", (int)sub_623F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Equip_Point_NoMsg", (int)sub_624060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Equip_Validity", (int)sub_624230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_UserEquip_VisualID", (int)sub_624110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_RideEquip_VisualID_ByActivePoint", (int)sub_6242E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Equip_StrengthLevel", (int)sub_6245B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Item_Icon_Name", (int)sub_624CB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Item_Icon_NameByDataIndex", (int)sub_624E10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Gem_Level", (int)sub_624F90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_UserEquip_Current_Durability", (int)sub_625340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_UserEquip_Maximum_Durability", (int)sub_625290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_OtherPlayerEquip_VisualID", (int)sub_6256F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_OtherPlayerRideBag_Num", (int)sub_625810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_OtherPlayerRideBag_VisualID", (int)sub_625860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetLifeAbility_LimitExp", (int)sub_624440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Enhance_Cost", (int)sub_6253F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Update_Equip_VisualID", (int)sub_625520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Enchase_Confirm", (int)sub_625550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Enchase_Four_Confirm", (int)sub_625620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Equip_CurStrengthLevel", (int)sub_625980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "CloseStrengthMsgBox", (int)sub_625A30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Enchase_CloseMsgBox", (int)sub_625A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "ClearComposeItems", (int)sub_625A90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "CloseReIdentifyMsgBox", (int)sub_625AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "ShowSuperToolTip", (int)sub_625AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Is_PetEquip", (int)sub_626100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_PetEquip_Point", (int)sub_6261F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_PetEquip_Level", (int)sub_626710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "ClosePetEquipReIdentifyMsgBox", (int)sub_6260E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_PetEquip_EnhanceLevel", (int)sub_626340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_PetEquip_CurStrengthLevel", (int)sub_626660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "ClosePetEquipEnhanceMsgBox", (int)sub_625A50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetDiaowenId", (int)sub_626890, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedDiaoWenName", (int)sub_626CC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedDiaoWenDesc", (int)sub_626DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedDiaoWenGrade", (int)sub_626EE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Can_Diaowen", (int)sub_627000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquitDiaowenID", (int)sub_627800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquitDiaowenIDEx", (int)sub_627960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetReqMatforEquipDWLevelUp", (int)sub_627AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetDWAttrbyDWID", (int)sub_627DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquitDiaowenIndex", (int)sub_627EB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Can_DiaowenRongHe", (int)sub_6272C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "CheckDwAndEquipPoint", (int)sub_628120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "CanEquipDiaowen_Enchase", (int)sub_6275C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "CanEquipDiaowen_EnchaseEx", (int)sub_6276E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquipDiaowen_Name", (int)sub_627F70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "IsEquipHaveDiaowen", (int)sub_627460, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "IsEquipHaveDiaowenEx", (int)sub_627510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "ConfirmDiaowenShike", (int)sub_6282D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "ConfirmDiaowenRonghe", (int)sub_628730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "IsDiaowenPic", (int)sub_628B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "ConfirmDiaowenHecheng", (int)sub_628C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "ConfirmDiaowenQianghua", (int)sub_628E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "ConfirmDiaowenChaichu", (int)sub_629030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedDiaowenId", (int)sub_626A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedDiaowenIdEx", (int)sub_626B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "IsIndentify", (int)sub_629090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "CheckSuperWeaponCanEnsoul", (int)sub_629130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "CheckSuperWeaponCanAdvance", (int)sub_6291E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "CheckSuperWeaponCanStarUp", (int)sub_629290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "CheckSuperWeaponCanChangeVirsual", (int)sub_629340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedEquip_HoleCount", (int)sub_620150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedEquip_ItemTableIndex", (int)sub_620220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "IsWearedEquipDark", (int)sub_6202F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetYuanbaoRepairTimes", (int)sub_620490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "SetYuanbaoRepairTimes", (int)sub_6204D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "IsWearedEquipHXY", (int)sub_6203C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetSplitGem_GemIndex", (int)sub_621B90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_Equiped_Gem_Info", (int)sub_625110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "SplitWearedEquipGem_Update", (int)sub_6224C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GemContainer_Update", (int)sub_621DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetGemContainer_Gem", (int)sub_621C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_GemName", (int)sub_6251F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "SplitWearedEquipGem", (int)sub_6225C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "SplitWearedEquipOneGem", (int)sub_622740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "SplitWearedEquipGameIcon", (int)sub_622840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_OtherPlayerEquip_GemInfo", (int)sub_621DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Get_OtherPlayerEquip_GemContainerInfo", (int)sub_621FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "UpdateProductAction", (int)sub_6293F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Lua_RlOpRsList_Update", (int)sub_622130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Lua_RL_GetSkillOrderText", (int)sub_622270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedLongWen_Level", (int)sub_622960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedLongWen_Star", (int)sub_622A20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedLongWen_AttLevel", (int)sub_622AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedLongWen_AttClass", (int)sub_622C00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedDark_QualityGrade", (int)sub_622D50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedEquip_NeedLevel", (int)sub_623110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "CreateVirtualActionItem", (int)sub_629700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedDarkLY_StarLv", (int)sub_622E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedDarkLY_CuiduHP", (int)sub_622F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedDarkLY_CuiduPro", (int)sub_622FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetWearedDarkLY_CuiduHit", (int)sub_623060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "GetEquipRepairInfo", (int)sub_6231C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31960, "Lua_SetGemComposeNotify", (int)sub_61F310, 0);
  v52 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v368, &unk_C6A118);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v578, v52);
  LOBYTE(v660) = 35;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v578, (const struct LuaPlus::LuaObject *)dword_D31960);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "LifeAbility", (struct LuaPlus::LuaObject *)&v578);
  v53 = operator new(0x18u);
  v465 = v53;
  LOBYTE(v660) = 36;
  if ( v53 )
    v54 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v53);
  else
    v54 = 0;
  dword_D33068 = v54;
  LOBYTE(v660) = 35;
  v55 = LuaPlus::LuaObject::CreateTable(&v659, &v536, "GuildTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D33068, v55);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v536);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D33068,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D33068);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "Show_PopMemu", (int)sub_6A05B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "Show_OfficialPopMenu", (int)sub_6A0930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "CreateGuild", (int)sub_699430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskGuildList4Page", (int)sub_6A0280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskGuildNameList", (int)sub_6A0390, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "CreateGuildConfirm", (int)sub_699920, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskGuildDetailInfo", (int)sub_699CC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskAnyGuildDetailInfo", (int)sub_699E90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskGuildMembersInfo", (int)sub_699FE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "SetGuildOnTime", (int)sub_69A1B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "ShowCityBuildIntroduce", (int)sub_6A25B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskGuildFirstManInfo", (int)sub_69A3B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskGuildFirstManName", (int)sub_69A580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskAnyGuildMembersInfo", (int)sub_69A750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskGuildAppointPosInfo", (int)sub_69A8C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetGuildNum", (int)sub_69AAD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetTotalCityNum", (int)sub_69AB10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetGuildNumCurPage", (int)sub_69AE80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetGuildInfo", (int)sub_69AEC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "InviteToGuild", (int)sub_69B270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "JoinGuild", (int)sub_69B720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetMembersNum", (int)sub_69C070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetMembersInfo", (int)sub_69C2E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetMemberBak", (int)sub_69C860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetMyGuildInfo", (int)sub_69C8A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetAnyGuildMembersInfo", (int)sub_69CB50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetMyGuildDetailInfo", (int)sub_69D0A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetMyGuildPower", (int)sub_69E330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "KickGuild", (int)sub_69BAC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "RecruitGuild", (int)sub_69BD10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "ExchangeBangGong", (int)sub_69BF10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "PutGuildMoney", (int)sub_69BFC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "QuitGuild", (int)sub_69B8E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AdjustMemberAuth", (int)sub_69E5D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "DemisGuild", (int)sub_69F610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "DemisGuildOK", (int)sub_69F9E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "FixGuildInfo", (int)sub_69F0E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "DestoryGuild", (int)sub_69EFA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "SureKickGuild", (int)sub_6A15B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "CloseKickGuildBox", (int)sub_6A1810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "ReflashEquipPoint", (int)sub_6A1830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "SortAnyGuildMembersByPosition", (int)sub_6A1950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "Sort2UnSortIndex", (int)sub_6A1E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetZoneWorldID", (int)sub_6A2550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetYXstate", (int)sub_69AD20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetMyGuildName", (int)sub_69E2F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetJiaofeistate", (int)sub_69ADE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetShoudanApplystate", (int)sub_69AB50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskElectionLeader", (int)sub_6A3A50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetCampaignerinfo", (int)sub_6A3B40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetCampaignerNum", (int)sub_6A3C90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "VoteCampaigner", (int)sub_6A3D00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetCampaignerMyRank", (int)sub_6A3E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "RefreshCampaignerList", (int)sub_6A3F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "PrepareMembersInfomation", (int)sub_69FCB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetShowMembersIdx", (int)sub_69C1A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetShowTraineesIdx", (int)sub_69C240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "ToggleGuildDetailInfo", (int)sub_69FD30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "ToCloseClanInfo", (int)sub_69FD90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "ToCloseGuildInfo", (int)sub_69FD60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "ModifyGuildLeaveWord", (int)sub_69FDC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetGuildLeaveWord", (int)sub_6A00F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskGuildLeaveWord", (int)sub_6A0130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetGuildContri", (int)sub_6A0240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "CityRnameCheck", (int)sub_6A0D90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "SendCityRnameMsg", (int)sub_6A10E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "CityRnameConfirm", (int)sub_6A1220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "IsGuildKeptOneWeed", (int)sub_6A1380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskCurCustomPositionName", (int)sub_6A1F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "ClearCustomPositionName", (int)sub_6A1FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskModifyCustomPositionName", (int)sub_6A1FE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetCurCustomPositionName", (int)sub_6A23E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetMyPosition", (int)sub_6A2490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "SetFirstMan", (int)sub_69E9A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "UnSetFirstMan", (int)sub_69ED30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "IsAnyGuildMemberIdxValid", (int)sub_6A24D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetFieldBossNumber", (int)sub_6A25D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetFieldBossRankGuild", (int)sub_6A2660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetMemInfoIndexByGUID", (int)sub_6A0490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "ModifyCurZhanQi", (int)sub_6A28E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "IsChieforAss", (int)sub_6A2B40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "ZhanQiIsReached", (int)sub_6A2BB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "AskGuildGiftLog", (int)sub_6A2C20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "DeliverGuildGift", (int)sub_6A2DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "OpentGuildGiftUI", (int)sub_6A2F60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetGuildGiftLog", (int)sub_6A30B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetGuildGiftCount", (int)sub_6A3000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "TakeGift", (int)sub_6A32E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetGuildGiftSingleLog", (int)sub_6A35C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "RefreshGuildGiftSingleLog", (int)sub_6A34A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetGuildGiftLogOwnerName", (int)sub_6A37B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "GetGuildGiftSingleLogOwnerName", (int)sub_6A3880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33068, "SaveMyGuildName", (int)sub_6A3950, 0);
  v56 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v442, &unk_D33070);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v580, v56);
  LOBYTE(v660) = 37;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v580, (const struct LuaPlus::LuaObject *)dword_D33068);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Guild", (struct LuaPlus::LuaObject *)&v580);
  v57 = operator new(0x18u);
  v465 = v57;
  LOBYTE(v660) = 38;
  if ( v57 )
    v58 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v57);
  else
    v58 = 0;
  dword_D33050 = v58;
  LOBYTE(v660) = 37;
  v59 = LuaPlus::LuaObject::CreateTable(&v659, &v483, "GangTTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D33050, v59);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v483);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D33050,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D33050);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetGangTerritoryInfo", (int)sub_698290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetGangTerritoryNum", (int)sub_698240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetSelfGuildOnGangTerritoryInd", (int)sub_6987C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetCopyScenePlayerInfoByIdx", (int)sub_6988A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "IsBHSDZDGameOver", (int)sub_698A90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetCopySceneFirstKillerType", (int)sub_698AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetBHSDZDPK_Result_Info", (int)sub_698B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetTwoBHSDZDNameInCopyScene", (int)sub_698B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetBHSDZDPK_LeftTimes", (int)sub_698BE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "SetBMMainTargetByUIIdx", (int)sub_698C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetGangTVoteLeftHour", (int)sub_6986D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetGangTVoteLeftMinute", (int)sub_698720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33050, "GetGangTVoteLeftSecond", (int)sub_698770, 0);
  v60 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v402, &unk_D3304C);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v582, v60);
  LOBYTE(v660) = 39;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v582, (const struct LuaPlus::LuaObject *)dword_D33050);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "GangT", (struct LuaPlus::LuaObject *)&v582);
  v61 = operator new(0x18u);
  v465 = v61;
  LOBYTE(v660) = 40;
  if ( v61 )
    v62 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v61);
  else
    v62 = 0;
  dword_D33160 = v62;
  LOBYTE(v660) = 39;
  v63 = LuaPlus::LuaObject::CreateTable(&v659, &v534, "CityTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D33160, v63);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v534);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D33160,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D33160);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "InputCityName", (int)sub_6A8C10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "CreateCity", (int)sub_6A8DF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetPortInfo", (int)sub_6A8FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskCityManageInfo", (int)sub_6A92B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetCityManageInfo", (int)sub_6A93C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetBuildingInfo", (int)sub_6A9A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "DoBuilding", (int)sub_6AA1B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "DoConfirm", (int)sub_6AA410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetBaseInfo", (int)sub_6AA8B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "CalculateNeedMoney", (int)sub_6AAC20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskCityBuildingResearch", (int)sub_6AA730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskCityShop", (int)sub_6AACE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumCityShop", (int)sub_6AAE10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetCityShopInfo", (int)sub_6AB020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "DoCityShop", (int)sub_6AB2B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumCityEnemy", (int)sub_6AB470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumBattleGuild", (int)sub_6AB7E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetEnemyNum", (int)sub_6ABB10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskEnemyList", (int)sub_6ABBF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetBattleNum", (int)sub_6ABD40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskBattleList", (int)sub_6ABE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "SendAddEnemyMsg", (int)sub_6ACBC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "SendAddGuildBattleMsg", (int)sub_6ACE00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "ReponseGuildBattle", (int)sub_6AD060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "SelectGuildBattle", (int)sub_6AD290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetAttackGuildName", (int)sub_6ADCC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "OpenAddEnemyDlg", (int)sub_6ABF80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "OpenAddBattleDlg", (int)sub_6AC360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "OpenGuildWarDlg", (int)sub_6AC4B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "OpenNewGuildWarDlg", (int)sub_6AC4D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskGuildBattleScore", (int)sub_6AD350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetGuildBattleScore", (int)sub_6AD490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetCityMissonMgrInfo", (int)sub_6AC570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "SetCityMissonMgrInfo", (int)sub_6AC7A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "SendCityMissonMgr", (int)sub_6ACA40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumGuildShop", (int)sub_6AEFD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetGuildShopInfo", (int)sub_6AF1E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "DoGuildShopBuy", (int)sub_6AF4F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "IsGuildShopMultiBuy", (int)sub_6AF7D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetWeekDuanWei", (int)sub_6AF960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskHonourShopData", (int)sub_6AF9B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "UpdateHonourShopData", (int)sub_6AFA40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetHonourShopItemNum", (int)sub_6AFBD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetHonourShopItemLayerNum", (int)sub_6AFCD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumHonourShop", (int)sub_6AFDE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetHonourShopInfo", (int)sub_6AFFF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "DoHonourShopBuy", (int)sub_6B0220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "IsHonourShopMultiBuy", (int)sub_6B0390, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskYuanBaoShopData", (int)sub_6B0510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "UpdateYuanBaoShopData", (int)sub_6B05A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetYuanBaoShopItemNum", (int)sub_6B0730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetYuanBaoShopItemLayerNum", (int)sub_6B0830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumYuanBaoShop", (int)sub_6B0940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetYuanBaoShopInfo", (int)sub_6B0B50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "DoYuanBaoShopBuy", (int)sub_6B0D80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "IsYuanBaoShopMultiBuy", (int)sub_6B0EF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskKServerGuildList", (int)sub_6AE0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskKServerGuildEnemyList", (int)sub_6AE200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AddKServerEnemyList", (int)sub_6AE300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetGuildListWithCity", (int)sub_6AE780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetKServerWorldNum", (int)sub_6AE530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetKServerZoneWorldIdByIndex", (int)sub_6AE570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetKServerZoneWorldNameByIndex", (int)sub_6AE660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetGuildInfoBigWorld", (int)sub_6AE860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetGuildNumByZoneWorldId", (int)sub_6AEAC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetKServerEnemyInfo", (int)sub_6AEB80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetPhoenixPlainWarScore", (int)sub_6ADD50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "OpenPhoenixPlainWarScoreSingleTable", (int)sub_6AC4F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "OpenPhoenixPlainWarScoreMultiTable", (int)sub_6AC510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "ClosePhoenixPlainWarScoreSingleTable", (int)sub_6AC530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "ClosePhoenixPlainWarScoreMultiTable", (int)sub_6AC550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "ClearPhoenixPlainWarScore", (int)sub_6AE0A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskBattleRankListGeneral", (int)sub_6B1070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskBattleRankListByGuild", (int)sub_6B13E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskBattleRankListByIndex", (int)sub_6B1220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskBattleRankListRival", (int)sub_6B13F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumBattleRankUserList", (int)sub_6B15D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumBattleRankList", (int)sub_6B18B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetBattleRankListNum", (int)sub_6B1F70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetBattleRankRivalListNum", (int)sub_6B1FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumBattleRankRivalUserList", (int)sub_6B1FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "OpenGuildBattleListDlg", (int)sub_6B2250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskBattleRankListByIndex_K", (int)sub_6B2290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumBattleRankList_K", (int)sub_6B2730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "EnumBattleRankUserList_K", (int)sub_6B2450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "GetBattleRankListNum_K", (int)sub_6B2DF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskBattleRankListRival_K", (int)sub_6B2E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "IsBattleOver", (int)sub_6B3010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "IsBattleOver_K", (int)sub_6B30F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskGuildBattleHisInfo", (int)sub_6B4D30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "AskGuildBattleHisData", (int)sub_6B4F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33160, "UpdateGuildBattleHis", (int)sub_6B3240, 0);
  v64 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v440, &unk_D33168);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v584, v64);
  LOBYTE(v660) = 41;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v584, (const struct LuaPlus::LuaObject *)dword_D33160);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "City", (struct LuaPlus::LuaObject *)&v584);
  v65 = operator new(0x18u);
  v465 = v65;
  LOBYTE(v660) = 42;
  if ( v65 )
    v66 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v65);
  else
    v66 = 0;
  dword_D33E30 = v66;
  LOBYTE(v660) = 41;
  v67 = LuaPlus::LuaObject::CreateTable(&v659, &v499, "GuildLeagueTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D33E30, v67);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v499);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D33E30,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D33E30);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "ShowCreateWindow", (int)sub_6BC730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "ShowInfoWindow", (int)sub_6BC750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "ShowListWindow", (int)sub_6BC770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "ShowApplyListWindow", (int)sub_6BC790, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "ShowCreateConfirmWindow", (int)sub_6BC7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "ShowQuitConfirmWindow", (int)sub_6BC9B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "ShowMemberMenu", (int)sub_6BC9D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "Create", (int)sub_6BCC60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "AskEnter", (int)sub_6BCFE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "AnswerEnter", (int)sub_6BD0C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "Quit", (int)sub_6BD1C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "ChangeDescription", (int)sub_6BD250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "RequestList", (int)sub_6BD500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "RequestInfo", (int)sub_6BD590, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "RequestApplyList", (int)sub_6BD620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "FireGuild", (int)sub_6BD6B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetID", (int)sub_6BD800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetName", (int)sub_6BD840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetDescription", (int)sub_6BD870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetChieftainGUID", (int)sub_6BD8A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetChieftain", (int)sub_6BD930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetCreator", (int)sub_6BD960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetCreateTime", (int)sub_6BD990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetUserCount", (int)sub_6BDA40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberCount", (int)sub_6BDA80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberName", (int)sub_6BDAC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberID", (int)sub_6BDB70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberEnterTime", (int)sub_6BDC30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberChieftainGUID", (int)sub_6BDD40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberChieftain", (int)sub_6BDE30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberUserCount", (int)sub_6BDEE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberCityName", (int)sub_6BDFA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberCityLevel", (int)sub_6BE050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberCityScene", (int)sub_6BE1B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetMemberCreateTime", (int)sub_6BE300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetLeagueCount", (int)sub_6BE440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetLeagueID", (int)sub_6BE480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetLeagueName", (int)sub_6BE540, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetLeagueCreateTime", (int)sub_6BE5F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetLeagueChieftainGUID", (int)sub_6BE700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetLeagueChieftain", (int)sub_6BE7F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetLeagueMemberCount", (int)sub_6BE8A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetLeagueDescription", (int)sub_6BE960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetApplyGuildCount", (int)sub_6BEA10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetApplyGuildName", (int)sub_6BEA50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetApplyGuildID", (int)sub_6BEB00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetApplyGuildChieftain", (int)sub_6BEBC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetApplyGuildCreateTime", (int)sub_6BEC70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetApplyGuildCity", (int)sub_6BED80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetApplyGuildLevel", (int)sub_6BEE30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetApplyGuildUserCount", (int)sub_6BEEF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E30, "GetApplyGuildDescription", (int)sub_6BEFB0, 0);
  v68 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v382, &off_C72748);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v586, v68);
  LOBYTE(v660) = 43;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v586, (const struct LuaPlus::LuaObject *)dword_D33E30);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "GuildLeague", (struct LuaPlus::LuaObject *)&v586);
  v69 = operator new(0x18u);
  v465 = v69;
  LOBYTE(v660) = 44;
  if ( v69 )
    v70 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v69);
  else
    v70 = 0;
  dword_D31AC0 = v70;
  LOBYTE(v660) = 43;
  v71 = LuaPlus::LuaObject::CreateTable(&v659, &v532, "PlayerPackage", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31AC0, v71);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v532);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31AC0,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31AC0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "EnumItem", (int)sub_630B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "OpenStallSaleFrame", (int)sub_630FE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSplitSum", (int)sub_631430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "SplitItem", (int)sub_631470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "CancelSplitItem", (int)sub_631580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "PackUpPacket", (int)sub_631620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSplitName", (int)sub_631C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "OpenPetList", (int)sub_631CC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "OpenLockFrame", (int)sub_631CF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lock", (int)sub_631D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsLock", (int)sub_632570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsPetLock", (int)sub_632610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetPUnlockElapsedTime_Pet", (int)sub_6326F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsGoodsProtect_Pet", (int)sub_6327F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "PickAllItem", (int)sub_632890, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagPosByItemIndex", (int)sub_6328B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetItemTableIndex", (int)sub_632930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetItemTableIndexByTemBank", (int)sub_6329D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetItemSubTableIndex", (int)sub_632A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetGemChangeRule", (int)sub_632B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsMaterial", (int)sub_632BE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsGem", (int)sub_632C80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetItemGrade", (int)sub_632E20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "UseItem", (int)sub_632EE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "FindFirstBindedItemIdxByIDTable", (int)sub_633270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "CountAvailableItemByIDTable", (int)sub_633320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetItemBindStatusByIndex", (int)sub_6333B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "OpenStengMsgBox", (int)sub_633440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "OpenReIdentifyMsgBox", (int)sub_6334D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "UseTulingzhuSetpos", (int)sub_633040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsBagItemDark", (int)sub_633540, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagItemDarkLevel", (int)sub_6335F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsBagItemHXY", (int)sub_6336A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "OpenPetEquipReIdentifyMsgBox", (int)sub_633750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "OpenPetEquipEnhanceMsgBox", (int)sub_6337C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetKfsAttrEx", (int)sub_6338E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Kfs_Op_Do", (int)sub_633A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsBagItemKFS", (int)sub_633EE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsBagItemXSZQ", (int)sub_633830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagKfsData", (int)sub_633F90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetKfsDataOnEquip", (int)sub_634240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagKfsSkill", (int)sub_6344E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagKfsSkillNum", (int)sub_6345B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagKfsAttrExUpMoney", (int)sub_634660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagKfsSkillUpMoney", (int)sub_634780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagKfsSlotMoney", (int)sub_6348B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagKfsAttrExNum", (int)sub_6349B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagKfsAttrExUpItem", (int)sub_634AA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetItemName", (int)sub_634BC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetEquipItemName", (int)sub_634C90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetPneumaItemName", (int)sub_634D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagKfsSkillUpSkill", (int)sub_634E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagKfsSkillUpItem", (int)sub_634F70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_IsBagItemRL", (int)sub_635090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_IsBagItemRS", (int)sub_635140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagRlExAttr", (int)sub_6351F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagItemRl_Rs", (int)sub_6359A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagItemRl_RsColor", (int)sub_635AF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagItemRl_RsLevel", (int)sub_635C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagItemRsColor", (int)sub_635E40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagItemRsLevel", (int)sub_635F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagItemRl_Grade", (int)sub_636020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagItemRl_BuffGroupID", (int)sub_635D90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagItemRl_StarInfo", (int)sub_636120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_IsBagItemHXY", (int)sub_6365D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagItemHxyType", (int)sub_636680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagEquipNeedLevel", (int)sub_636770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_IsBagItemBelongZZType", (int)sub_636820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagEquipHandMakeLevel", (int)sub_6368D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagEquipHandMakeType", (int)sub_636980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagItemEquipPoint", (int)sub_636A30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_IsBagItemEquip", (int)sub_63BFF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_IsBagItemWeapon", (int)sub_63C090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_IsBagItemNeedIdentify", (int)sub_63C140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagZZItemZZRate", (int)sub_63C1F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagZZItemExtAttrCount", (int)sub_63C370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetBagZZItemExtAttr", (int)sub_63C410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsProtectGoods", (int)sub_636AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsProtectGoodsByItemTableIndex", (int)sub_636B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "CheckDiaowenHechengMat", (int)sub_636C50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetDiaowenHechengMat", (int)sub_636ED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetGoldTickValueByIndex", (int)sub_6370D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagItemName", (int)sub_6371A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSheliziExp", (int)sub_637220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBankItemName", (int)sub_6372B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetEquipBagItemName", (int)sub_637330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsGemInBank", (int)sub_632D50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagItemNum", (int)sub_6373B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsYubaoTradeItem", (int)sub_637440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "SellCurrItem", (int)sub_6374E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "UseDunJiaTianShuSetpos", (int)sub_637570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "UseDunJiaQiShuSetpos", (int)sub_637830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetDunJiaShuPosInfo", (int)sub_637DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "UseDunJiaTianShuChuanSong", (int)sub_638410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "UseDunJiaQiShuChuanSong", (int)sub_6386D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "UseDunJiaTianShuBuChong", (int)sub_638C60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "UseDunJiaQiShuBuChong", (int)sub_638CE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetDunJiaShuVIPPosInfo", (int)sub_638090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "UseDunJiaVIPSetpos", (int)sub_637AF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "UseDunJiaVIPChuanSong", (int)sub_638990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetKVKItemTradeType", (int)sub_638D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsBagItemLW", (int)sub_6390D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lw_Op_Do", (int)sub_639180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagLWData", (int)sub_639350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagLWBaseTxtInfo", (int)sub_639580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagLWBaseTxtInfoByIndex", (int)sub_6397A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagLWStarUpInfo", (int)sub_6399D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetBagLWAttrExInfo", (int)sub_639CD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetZhongXiaPanInfo", (int)sub_638360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetValidLwForLevelUp", (int)sub_638E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetValidZwForLevelUp", (int)sub_638FC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponEnsoulMaterialCount", (int)sub_63A0A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponEnsoulMaterialID", (int)sub_63A150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponAdvanceMaterialCount", (int)sub_63A360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponAdvanceMaterialID", (int)sub_63A410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponAdvanceMaterialIDNum", (int)sub_63A590, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponStarUpMaterialCount", (int)sub_63A6F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponStarUpMaterialID", (int)sub_63A7A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponEnsoulCashCost", (int)sub_63A200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponEnsoulMaterialName", (int)sub_63A2B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponAdvanceCashCost", (int)sub_63A640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponStarUpCashCost", (int)sub_63A880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponChangeVirsualCashCost", (int)sub_63A930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponQual", (int)sub_63A9E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetEquipSuperWeaponQual", (int)sub_63AA90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponAdvanceMaterialName", (int)sub_63A4F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponQualityDownBagSpaceNeed", (int)sub_63AF20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponQualityDownMoneyCost", (int)sub_63B000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeaponQualityDownMaterialNum", (int)sub_63B0E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetSuperWeapon9WG", (int)sub_63AB30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "CheckIsCanQualityDown", (int)sub_63B1C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "CheckIsSuperWeapon", (int)sub_63AE40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsEquipLocked", (int)sub_63B2A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetStrengthenLevel", (int)sub_63B350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsHaveAttaProperty", (int)sub_63B3F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetEquipLevelUpInfo", (int)sub_63B490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IsChongLouItem", (int)sub_63B6B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetInfantCard_Qual", (int)sub_63B760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetInfantCard_EnhanceLevel", (int)sub_63B810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetInfantCard_SuccRate", (int)sub_63B8C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetInfantCard_CurValue", (int)sub_63B970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetInfantCard_NextValue", (int)sub_63BA20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetInfatnCard_CardType", (int)sub_63BAD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetItemVisual", (int)sub_63BB80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetUnLockItemCount", (int)sub_63BDA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetUnLockBindItemCount", (int)sub_63BE60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetLockItemCount", (int)sub_63BF30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "GetWuFangFuUseNum", (int)sub_6364C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "IdentifyConfirm", (int)sub_63C720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31AC0, "Lua_GetItemAttachParam", (int)sub_63C860, 0);
  v72 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v438, &unk_D31ABC);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v588, v72);
  LOBYTE(v660) = 45;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v588, (const struct LuaPlus::LuaObject *)dword_D31AC0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "PlayerPackage", (struct LuaPlus::LuaObject *)&v588);
  v73 = operator new(0x18u);
  v465 = v73;
  LOBYTE(v660) = 46;
  if ( v73 )
    v74 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v73);
  else
    v74 = 0;
  dword_D35C98 = v74;
  LOBYTE(v660) = 45;
  v75 = LuaPlus::LuaObject::CreateTable(&v659, &v467, "SuperTooltips", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D35C98, v75);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v467);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D35C98,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D35C98);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "IsPresent", (int)sub_722EF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetTitle", (int)sub_722F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetIconName", (int)sub_722F60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetDesc1", (int)sub_722F90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetDesc2", (int)sub_722FC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetDesc3", (int)sub_722FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetDesc4", (int)sub_723020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetDesc5", (int)sub_723050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetDesc6", (int)sub_723090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetPUnlockElapsedTime", (int)sub_7230D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetEquipQual", (int)sub_723110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetGoodsProtect_Goods", (int)sub_723170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetTypeDesc", (int)sub_7231B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetTypeIsZhenShouDan", (int)sub_723210, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetGemHoleCounts", (int)sub_7232D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetGemIcon1", (int)sub_723330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetGemIcon2", (int)sub_723370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetGemIcon3", (int)sub_7233B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetGemIcon4", (int)sub_7233F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetDiaowenIcon", (int)sub_723430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetDiaowenIconEx", (int)sub_723470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetMoney1", (int)sub_7234B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetMoney1Type", (int)sub_723550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetMoney2", (int)sub_7235D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetPropertys", (int)sub_723670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetAuthorInfo", (int)sub_7236D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetExplain", (int)sub_723730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "SendAskItemInfoMsg", (int)sub_723770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "IsTransferItem", (int)sub_7238B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "IsTransferPneuma", (int)sub_723920, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetActionID", (int)sub_723990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetYuanbaoTradeFlag", (int)sub_7239D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GeKVKExchangeFlag", (int)sub_723A10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetGuiShiItemFlag", (int)sub_723A50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetGuiShiJiaoYiFlag", (int)sub_723A90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetIsShowJiaoZi", (int)sub_723AD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetEquipMasterFlag", (int)sub_723B10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetEquipMasterText", (int)sub_723B50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetBaiShouLevelText", (int)sub_723B90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetZhiZunEquipText", (int)sub_725930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetZhiZunEquipType", (int)sub_725970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "ShowCmp2WindowMain", (int)sub_723BD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "ShowCmp2WindowSub", (int)sub_723FC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "Cmp2WindowMainMove", (int)sub_724310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "Cmp2WindowSubMove", (int)sub_7245A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "CloseCmp2WindowMain", (int)sub_724790, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "CloseCmp2WindowSub", (int)sub_7247B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "ShowCmpWindowMain", (int)sub_7247D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "ShowCmpWindowSub", (int)sub_724C70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "CloseCmpWindowMain", (int)sub_725080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "CloseCmpWindowSub", (int)sub_7250A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "ShowToolTipsWithAlt", (int)sub_7250C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "ShowToolTips2WithAlt", (int)sub_7251C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetSweetWordsID", (int)sub_7255D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "Infant_IsInfantCard", (int)sub_725610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "Infant_GetCardData", (int)sub_725640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "Campaign_GetItemData", (int)sub_7257D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetBieYeFurniture1", (int)sub_7259B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetBieYeFurniture2", (int)sub_7259F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "GetBieYeFurniture3", (int)sub_725A30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "Lua_GetXingJuanAttr", (int)sub_725A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35C98, "Lua_GetXingJuanSlotAttr", (int)sub_725CC0, 0);
  v76 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v400, &unk_D35F90);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v590, v76);
  LOBYTE(v660) = 47;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v590, (const struct LuaPlus::LuaObject *)dword_D35C98);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "SuperTooltips2", (struct LuaPlus::LuaObject *)&v590);
  v77 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v436, &unk_D36860);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v592, v77);
  LOBYTE(v660) = 48;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v592, (const struct LuaPlus::LuaObject *)dword_D35C98);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "SuperTooltips2_Cmp1", (struct LuaPlus::LuaObject *)&v592);
  v78 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v372, &unk_D36B50);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v594, v78);
  LOBYTE(v660) = 49;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v594, (const struct LuaPlus::LuaObject *)dword_D35C98);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "SuperTooltips2_Cmp2", (struct LuaPlus::LuaObject *)&v594);
  v79 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v434, &unk_D35CA0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v596, v79);
  LOBYTE(v660) = 50;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v596, (const struct LuaPlus::LuaObject *)dword_D35C98);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "SuperTooltips", (struct LuaPlus::LuaObject *)&v596);
  v80 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v398, &unk_D36280);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v598, v80);
  LOBYTE(v660) = 51;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v598, (const struct LuaPlus::LuaObject *)dword_D35C98);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "SuperTooltips_Cmp1", (struct LuaPlus::LuaObject *)&v598);
  v81 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v432, &unk_D36570);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v600, v81);
  LOBYTE(v660) = 52;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v600, (const struct LuaPlus::LuaObject *)dword_D35C98);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "SuperTooltips_Cmp2", (struct LuaPlus::LuaObject *)&v600);
  v82 = operator new(0x18u);
  v465 = v82;
  LOBYTE(v660) = 53;
  if ( v82 )
    v83 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v82);
  else
    v83 = 0;
  dword_D32BC0 = v83;
  LOBYTE(v660) = 52;
  v84 = LuaPlus::LuaObject::CreateTable(&v659, &v530, "AttrCompare", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32BC0, v84);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v530);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D32BC0,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D32BC0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC0, "GetAttrCmpStr", (int)sub_686A20, 0);
  v85 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v380, &off_C6F028);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v602, v85);
  LOBYTE(v660) = 54;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v602, (const struct LuaPlus::LuaObject *)dword_D32BC0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "AttrCompare1_1", (struct LuaPlus::LuaObject *)&v602);
  v86 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v430, &off_C6F044);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v604, v86);
  LOBYTE(v660) = 55;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v604, (const struct LuaPlus::LuaObject *)dword_D32BC0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "AttrCompare1_2", (struct LuaPlus::LuaObject *)&v604);
  v87 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v396, &off_C6F060);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v606, v87);
  LOBYTE(v660) = 56;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v606, (const struct LuaPlus::LuaObject *)dword_D32BC0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "AttrCompare2_1", (struct LuaPlus::LuaObject *)&v606);
  v88 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v428, &off_C6F07C);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v608, v88);
  LOBYTE(v660) = 57;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v608, (const struct LuaPlus::LuaObject *)dword_D32BC0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "AttrCompare2_2", (struct LuaPlus::LuaObject *)&v608);
  v89 = operator new(0x18u);
  v465 = v89;
  LOBYTE(v660) = 58;
  if ( v89 )
    v90 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v89);
  else
    v90 = 0;
  dword_D31EA8 = v90;
  LOBYTE(v660) = 57;
  v91 = LuaPlus::LuaObject::CreateTable(&v659, &v497, "StallSale", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31EA8, v91);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v497);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31EA8,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31EA8);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "IsPresent", (int)sub_66B8D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetPosTax", (int)sub_66B930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetTradeTax", (int)sub_66B980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetCoinType", (int)sub_66B9D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "ReferItemPrice", (int)sub_66BA20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "ModifStallName", (int)sub_66BE00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "ModifItemPrice", (int)sub_66C100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "CloseStall", (int)sub_66C2C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "ConfirmRemoveStall", (int)sub_66C2A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "ItemReprice", (int)sub_66C4E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "AgreeBeginStall", (int)sub_66C740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "DeleteItem", (int)sub_66C920, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetPrice", (int)sub_66CB70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "OpenMessageSale", (int)sub_66CDD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "ApplyAd", (int)sub_66CE70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "CloseStallMessage", (int)sub_66D3D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetStallName", (int)sub_66D410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetAdvertise", (int)sub_66D450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetGuid", (int)sub_66D5B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetItemNum", (int)sub_66D640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetPetNum", (int)sub_66D6E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "EnumPet", (int)sub_66D720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "PetUpStall", (int)sub_66D8A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "PetReprice", (int)sub_66DB00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetDefaultPage", (int)sub_66DD70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "SetDefaultPage", (int)sub_66DDC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "ViewPetDesc", (int)sub_66DE90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "SetSelectPet", (int)sub_66E020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "UnlockSelItem", (int)sub_66E080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "OpenPetList", (int)sub_66E160, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetStallOfflineState", (int)sub_66E180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "SetStallOfflineState", (int)sub_66E1D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetStallType", (int)sub_66E0E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetCanSOCoin", (int)sub_66E2A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetCanSOYuanBao", (int)sub_66E310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EA8, "GetNeedAcPointByLevel", (int)sub_66E380, 0);
  v92 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v364, &unk_D31EA4);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v610, v92);
  LOBYTE(v660) = 59;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v610, (const struct LuaPlus::LuaObject *)dword_D31EA8);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "StallSale", (struct LuaPlus::LuaObject *)&v610);
  v93 = operator new(0x18u);
  v465 = v93;
  LOBYTE(v660) = 60;
  if ( v93 )
    v94 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v93);
  else
    v94 = 0;
  dword_D31E9C = v94;
  LOBYTE(v660) = 59;
  v95 = LuaPlus::LuaObject::CreateTable(&v659, &v528, "StallBuy", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31E9C, v95);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v528);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31E9C,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31E9C);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "IsPresent", (int)sub_66A200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetTradeTax", (int)sub_66A260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetCoinType", (int)sub_66A2B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "OpenStall", (int)sub_66A300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetPrice", (int)sub_66A500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "BuyItem", (int)sub_66A710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "OpenMessageBuy", (int)sub_66A860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetStallName", (int)sub_66A9F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetAdvertise", (int)sub_66AA30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "CloseStallMessage", (int)sub_66AB50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetGuid", (int)sub_66AB70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetStallerName", (int)sub_66AC00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetItemNum", (int)sub_66AC40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetPetNum", (int)sub_66ACE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "EnumPet", (int)sub_66AD20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetDefaultPage", (int)sub_66AED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetSOState", (int)sub_66AF20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "BuyPet", (int)sub_66AF70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "IsHaveObject", (int)sub_66B0B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetPrePrice", (int)sub_66B270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "SetPrePrice", (int)sub_66B2C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "OpenMessageFrame", (int)sub_66A940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetStallType", (int)sub_66B320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "GetItemName", (int)sub_66A680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E9C, "CheckItemPrice", (int)sub_66B3A0, 0);
  v96 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v426, &unk_D31E98);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v612, v96);
  LOBYTE(v660) = 61;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v612, (const struct LuaPlus::LuaObject *)dword_D31E9C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "StallBuy", (struct LuaPlus::LuaObject *)&v612);
  v97 = operator new(0x18u);
  v465 = v97;
  LOBYTE(v660) = 62;
  if ( v97 )
    v98 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v97);
  else
    v98 = 0;
  dword_D31E94 = v98;
  LOBYTE(v660) = 61;
  v99 = LuaPlus::LuaObject::CreateTable(&v659, &v481, "StallBbs", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31E94, v99);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v481);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31E94,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31E94);
  sub_877220((LuaPlus::LuaObject *)dword_D31E94, "GetMessageNum", (int)sub_669160, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E94, "EnumMessage", (int)sub_6692F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E94, "AddMessage", (int)sub_6696C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E94, "ReplyMessage", (int)sub_669C60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E94, "DeleteMessageByID", (int)sub_66A0D0, 0);
  v100 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v394, &unk_D31E90);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v614, v100);
  LOBYTE(v660) = 63;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v614, (const struct LuaPlus::LuaObject *)dword_D31E94);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "StallBbs", (struct LuaPlus::LuaObject *)&v614);
  v101 = operator new(0x18u);
  v465 = v101;
  LOBYTE(v660) = 64;
  if ( v101 )
    v102 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v101);
  else
    v102 = 0;
  dword_D35A7C = v102;
  LOBYTE(v660) = 63;
  v103 = LuaPlus::LuaObject::CreateTable(&v659, &v526, "MissionReply", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D35A7C, v103);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v526);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D35A7C,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D35A7C);
  sub_877220((LuaPlus::LuaObject *)dword_D35A7C, "IsPresent", (int)sub_6D3A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A7C, "OpenPetFrame", (int)sub_6D3AD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A7C, "OnContinue", (int)sub_6D3AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A7C, "EnumItem", (int)sub_6D3BB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A7C, "DoAction", (int)sub_6D3D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A7C, "OpenSecondConfirmFrame", (int)sub_6D3DF0, 0);
  v104 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v424, &unk_D35A78);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v616, v104);
  LOBYTE(v660) = 65;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v616, (const struct LuaPlus::LuaObject *)dword_D35A7C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "MissionReply", (struct LuaPlus::LuaObject *)&v616);
  v105 = operator new(0x18u);
  v465 = v105;
  LOBYTE(v660) = 66;
  if ( v105 )
    v106 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v105);
  else
    v106 = 0;
  dword_D35B18 = v106;
  LOBYTE(v660) = 65;
  v107 = LuaPlus::LuaObject::CreateTable(&v659, &v495, "Talk", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D35B18, v107);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v495);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D35B18,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D35B18);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetChannelNumber", (int)sub_6F8E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetChannel", (int)sub_6F8E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetChannelHeader", (int)sub_6F93D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SendChatMessage", (int)sub_6F9710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "InsertHistory", (int)sub_6FAD30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SetMaxSaveNumber", (int)sub_6FB410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SetDisappearTime", (int)sub_6FB480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "CreateTab", (int)sub_6FB4F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ConfigTab", (int)sub_6FB560, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "CreateTabFinish", (int)sub_6FB720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ConfigTabFinish", (int)sub_6FBD30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SaveTab", (int)sub_6FB950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ClearTab", (int)sub_6FBBF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetChannelType", (int)sub_6FBED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SelectFaceMotion", (int)sub_6FC000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SelectTextColor", (int)sub_6FC2C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SaveOldTalkMsg", (int)sub_6FC580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ChangeCurrentChannel", (int)sub_6FC990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ModifyChatTxt", (int)sub_6FCE30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ShowContexMenu", (int)sub_6FD410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ContexMenuTalk", (int)sub_6FDE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetCurrentSelectName", (int)sub_6FE050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetTalkTemplateString", (int)sub_6FE570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "EnumChatMood", (int)sub_6FE7F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "EnumDoubleChatMood", (int)sub_6FE970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "IsValidChatActionByIndex", (int)sub_6FEAE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "CanDoDoubleAction", (int)sub_6FEB80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "DoDoubleActionByIndex", (int)sub_6FED90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "IsValidChatActionString", (int)sub_6FEE60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "CanDoDoubleAction_Bar", (int)sub_6FF340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ShowChatMood", (int)sub_6FF550, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "HandleMenuAction", (int)sub_6FE090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ShowPingBi", (int)sub_6FF5C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetPingBiNum", (int)sub_6FF630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetPingBiName", (int)sub_6FF670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "DelPingBi", (int)sub_6FF710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetCurInputLanguage", (int)sub_6FF7A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SetCurTab", (int)sub_6FF800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SetTabCfg", (int)sub_6FF890, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "MoveTabHisQue", (int)sub_6FF9D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetHyperLinkString", (int)sub_6FFA60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "IsFenpingOpen", (int)sub_700B60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "HandleMainBarAction", (int)sub_6FFE50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "HandleHistoryAction", (int)sub_6FFEE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SaveChatHistory", (int)sub_700140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SetEditboxActive", (int)sub_700200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "DisclosureToGM", (int)sub_700220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ShowContexMenu4Speaker", (int)sub_6FD7C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "HideContexMenu4Speaker", (int)sub_6FDAE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "OpenSpeakerDlg", (int)sub_700750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetCurTab", (int)sub_7007D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "OpenFenpingConfigDlg", (int)sub_700840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "OpenFenpingConfigDlgChatFrame", (int)sub_700810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "CreateFenping", (int)sub_7008E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "CloseFenping", (int)sub_7009F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ConfigFenping", (int)sub_700A30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ClearFenpingHisQue", (int)sub_700B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ShowContexMenuFromTeamBoard", (int)sub_6FDB00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "SaveIMChatHistory", (int)sub_701EA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "IshaveGSIMMsg", (int)sub_700BA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "IshaveGSIMMsgNew", (int)sub_700BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "IsInGSService", (int)sub_700C50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetGSState", (int)sub_700CD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetNewGSState", (int)sub_700D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetGSName", (int)sub_700D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetNewGSName", (int)sub_700E00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetGSPic", (int)sub_700E40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetNewGSPic", (int)sub_700ED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "OpenGSIMMsg", (int)sub_700F60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "haveReadGSIMMsg", (int)sub_701090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "haveReadGSIMMsgNew", (int)sub_7010B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GSChat_SendMsg", (int)sub_7010E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GSChat_SendMsgNew", (int)sub_701480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GSChat_SendScore", (int)sub_701820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GSChat_SendScoreNew", (int)sub_7018E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "IsCanScore", (int)sub_701A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "IsCanScoreNew", (int)sub_701AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetGSIMChatCount", (int)sub_701B20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetNewGSIMChatCount", (int)sub_701B70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetGSIMChatByIndex", (int)sub_701BC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetNewGSIMChatByIndex", (int)sub_701C90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetNewGSMood", (int)sub_701D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "AskGSInfoNew", (int)sub_701DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "GetGSInfoIsRetNew", (int)sub_701E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "ShowContexMenu4SecretSpeaker", (int)sub_702380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35B18, "DelUserByIndex", (int)sub_6F9020, 0);
  v108 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v378, &unk_D35B20);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v618, v108);
  LOBYTE(v660) = 67;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v618, (const struct LuaPlus::LuaObject *)dword_D35B18);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Talk", (struct LuaPlus::LuaObject *)&v618);
  v109 = operator new(0x18u);
  v465 = v109;
  LOBYTE(v660) = 68;
  if ( v109 )
    v110 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v109);
  else
    v110 = 0;
  dword_D31A50 = v110;
  LOBYTE(v660) = 67;
  v111 = LuaPlus::LuaObject::CreateTable(&v659, &v524, "NpcShop", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31A50, v111);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v524);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31A50,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31A50);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "Close", (int)sub_62DB10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetNpcId", (int)sub_62DB30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "EnumCallBackItem", (int)sub_62DB80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetCallBackNum", (int)sub_62DC80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "EnumItemPrice", (int)sub_62DCD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "EnumItemPriceRecently", (int)sub_62DD60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "EnumItemPriceJiYuanBooth", (int)sub_62DDF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "EnumItemMaxOverlay", (int)sub_62DE80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "EnumItemName", (int)sub_62DF20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "EnumItemID", (int)sub_62DFB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "EnumItemNumber", (int)sub_62E050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "BulkBuyItem", (int)sub_62E0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "BuyItemForFriend", (int)sub_62EB60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "BuyItemFromFittingRoom", (int)sub_62EE50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "BuyItemFromJiYuanShop", (int)sub_62EF90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "BuyItemWithOutConfirm", (int)sub_62F110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetShopType", (int)sub_62F160, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetRepairAllPrice", (int)sub_62F3D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetIsShopReorder", (int)sub_62F4B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "CloseConfirm", (int)sub_62F500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetBuyDirectly", (int)sub_62F520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetBuyDirectly", (int)sub_62F5F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "BindYuanBaoNotEnough", (int)sub_62F900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetUseYBForBind", (int)sub_62F750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetUseYBForBind", (int)sub_62F7A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetNotPayNotice", (int)sub_62F7E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetNotPayNotice", (int)sub_62F830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetAutoPutOnBuyStuff", (int)sub_62F870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetAutoPutOnBuyStuff", (int)sub_62F8C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetPresentXuanDirectly", (int)sub_62FAD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetPresentXuanDirectly", (int)sub_62FB20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetIsXuanShopType", (int)sub_62FB60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetIsXuanShopType", (int)sub_62FBB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetFriendID_PS", (int)sub_62FBF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetFriendID_PS", (int)sub_62FC90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetLiJinBuyDirectly", (int)sub_62FD20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetLiJinBuyDirectly", (int)sub_62FDF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetBWHonourBuyDirectly", (int)sub_62F630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetBWHonourBuyDirectly", (int)sub_62F680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetGuildShopBuyDirectly", (int)sub_62F6C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetGuildShopBuyDirectly", (int)sub_62F710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetGemLevelupDirectly", (int)sub_62FE30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetGemLevelupDirectly", (int)sub_62FE80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetFuJiangTLBuyDirectly", (int)sub_62FEC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetFuJiangTLBuyDirectly", (int)sub_62FF90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetResignDirectly", (int)sub_62FFD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetResignDirectly", (int)sub_6300A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetFaTieBuyDirectly", (int)sub_6300E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetFaTieBuyDirectly", (int)sub_6301B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetCreditShopBuyDirectly", (int)sub_6301F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetCreditShopBuyDirectly", (int)sub_6302C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetFurnitureComfirmDirectly", (int)sub_630300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetFurnitureComfirmDirectly", (int)sub_6303D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetFurnitureBankComfirmDirectly", (int)sub_630410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetFurnitureBankComfirmDirectly", (int)sub_6304E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetBieYePlantingComfirmDirectly", (int)sub_630520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetBieYePlantingComfirmDirectly", (int)sub_630670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetDWHechengDirectly", (int)sub_630710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetDWHechengDirectly", (int)sub_630760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetDWShikeDirectly", (int)sub_6307A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetDWShikeDirectly", (int)sub_6307F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetDWChaichuDirectly", (int)sub_630830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetDWChaichuDirectly", (int)sub_630880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "GetFurnitureTransferDirectly", (int)sub_6308C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A50, "SetFurnitureTransferDirectly", (int)sub_630900, 0);
  v112 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v422, &dword_C6AD28);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v620, v112);
  LOBYTE(v660) = 69;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v620, (const struct LuaPlus::LuaObject *)dword_D31A50);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "NpcShop", (struct LuaPlus::LuaObject *)&v620);
  v465 = operator new(0x18u);
  v464 = v465;
  LOBYTE(v660) = 70;
  if ( v465 )
  {
    sub_877440("SystemSetup", 0);
    v113 = v465;
    *(_DWORD *)v465 = &SCRIPT_SANDBOX::SystemSetup::`vftable';
    v113[1] &= 0xFFEFFFFF;
  }
  else
  {
    v465 = 0;
  }
  LOBYTE(v660) = 69;
  sub_8771E0("IsClassic", sub_6E6940);
  sub_8771E0("IsCameraSpecial", sub_6E6980);
  sub_8771E0("Display", sub_6E69C0);
  sub_8771E0("Sound", sub_6E69D0);
  sub_8771E0("OpenSetup", sub_6E69E0);
  sub_8771E0("ViewSetup", sub_6E6A00);
  sub_8771E0("SoundSetup", sub_6E6A20);
  sub_8771E0("UISetup", sub_6E6A40);
  sub_8771E0("InputSetup", sub_6E6A60);
  sub_8771E0("ControlModeSetup", sub_6E6AC0);
  sub_8771E0("InputSetupSwitch", sub_6E6AD0);
  sub_8771E0("InputSetup_OnOff", sub_6E6B50);
  sub_8771E0("SetChatType", sub_6E6C30);
  sub_8771E0("UseAcceCustomKey", sub_6E6CA0);
  sub_8771E0("ComeBackAcce", sub_6E6C90);
  sub_8771E0("GetInputSetup", sub_6E6CD0);
  sub_8771E0("GetAcceTip", sub_6E6E80);
  sub_8771E0("GameSetup", sub_6E6F90);
  sub_8771E0("GameHelp", sub_6E6FB0);
  sub_8771E0("BackGame", sub_6E6FC0);
  sub_8771E0("SaveCurAcceCustom", sub_6EE590);
  sub_8771E0("SetIsConfigChanged", sub_6EE500);
  sub_8771E0("GetIsConfigChanged", sub_6EE550);
  sub_8771E0("RevertAcceCustom", sub_6EE5A0);
  sub_8771E0("View_GetData", sub_6E6FD0);
  sub_8771E0("View_SetData", sub_6E74E0);
  sub_8771E0("GameGetData", sub_6E7A00);
  sub_8771E0("SaveGameSetup", sub_6E8050);
  sub_8771E0("GetChatSetting", sub_6E8FA0);
  sub_8771E0("SaveChatSetting", sub_6E90D0);
  sub_8771E0("AskPrivateInfo", sub_6E9870);
  sub_8771E0("ApplyPrivateInfo", sub_6E9880);
  sub_8771E0("GetPrivateInfo", sub_6E9BC0);
  sub_8771E0("OpenPrivatePage", sub_6E96F0);
  sub_8771E0("SetPrivateInfo", sub_6EA5B0);
  sub_8771E0("OpenEquipFrame", sub_6EB570);
  sub_8771E0("OpenPetFrame", sub_6EB690);
  sub_8771E0("GetCaredObjId", sub_6EB7B0);
  sub_8771E0("GetDoubleExp", sub_6EDB90);
  sub_8771E0("OpenRidePage", sub_6EE290);
  sub_8771E0("AskQingYuanData", sub_6ECF40);
  sub_8771E0("GetQingYuanData", sub_6EB800);
  sub_8771E0("GetQingYuanInfo", sub_6EBB30);
  sub_8771E0("SetQingYuanData", sub_6EBC90);
  sub_8771E0("SetQingYuanInfo", sub_6EBE50);
  sub_8771E0("ApplyQingYuanData", sub_6EBFE0);
  sub_8771E0("MatchQingYuanRen", sub_6EC080);
  sub_8771E0("GetQingYuanMatchCount", sub_6EC100);
  sub_8771E0("GetQingYuanMatchData", sub_6EC150);
  sub_8771E0("GetCharactZoneWorldId", sub_6EC460);
  sub_8771E0("AskTeamUp", sub_6EC5B0);
  sub_8771E0("QingYuanSayHello", sub_6EC730);
  sub_8771E0("GetQingYuanHelloType", sub_6ECA80);
  sub_8771E0("SetQingYuanHelloType", sub_6ECAD0);
  sub_8771E0("GetTimeInt", sub_6ECB30);
  sub_8771E0("GetQingYuanUITipFlag", sub_6ECFD0);
  sub_8771E0("SetQingYuanUITipFlag", sub_6ED020);
  sub_8771E0("QingYuanGetRelationType", sub_6ECD70);
  sub_8771E0("QingYuanGetHopeSex", sub_6ECEF0);
  sub_8771E0("QingYuanSetHopeSex", sub_6ECE90);
  sub_8771E0("QingYuanGetHelloToMeInfo", sub_6ED080);
  sub_8771E0("QingYuanCheckHelloCD", sub_6ED890);
  sub_8771E0("GetQingYuanMatchZoneId", sub_6EDAE0);
  sub_8771E0("Get_Display_DecoWeapon", sub_6EDFE0);
  sub_8771E0("Set_Display_DecoWeapon", sub_6EE020);
  sub_8771E0("Get_Display_Dress", sub_6EDEB0);
  sub_8771E0("Set_Display_Dress", sub_6EDF00);
  sub_8771E0("GetSubMenubarState", sub_6EE110);
  sub_8771E0("SetSubMenubarState", sub_6EE160);
  sub_8771E0("GetUpBar2State", sub_6EE240);
  sub_8771E0("OpenOtherWuhun", sub_6EE3B0);
  sub_8771E0("OpenOtherJingMai", sub_6EE3D0);
  sub_8771E0("OpenOtherMiji", sub_6EE440);
  sub_8771E0("OpenOtherShenDing", sub_6EE3F0);
  sub_8771E0("OpenOptimize", sub_6EE460);
  sub_8771E0("OptimizeConfirm", sub_6EE480);
  sub_8771E0("UpdateHeadMode", sub_6EE4B0);
  sub_8771E0("Lua_SetNonChatActive", sub_6E92F0);
  sub_8771E0("Lua_LogControlMode", sub_6E93F0);
  sub_8771E0("Lua_ViewSetupToFile", sub_6E94B0);
  sub_8771E0("CustomPlayerList", sub_6E94C0);
  sub_8771E0("GetCustomPlayerList", sub_6E95E0);
  sub_8771E0("GetShowWuhunObj", sub_6EE690);
  sub_8771E0("SetShowWuhunObj", sub_6EE5B0);
  v465 = operator new(4u);
  v464 = v465;
  LOBYTE(v660) = 71;
  if ( v465 )
  {
    sub_877260("Macro", 0);
    *(_DWORD *)v465 = &SCRIPT_SANDBOX::Macro::`vftable';
  }
  else
  {
    v465 = 0;
  }
  LOBYTE(v660) = 69;
  sub_8771A0("reloadsystemcolor", sub_6CDB50);
  sub_8771A0("sendhardchat", sub_6CDB60);
  sub_8771A0("pushball", sub_6CDD00);
  sub_8771A0("setfog", sub_6CDE20);
  sub_8771A0("reloadscript", sub_6CDF40);
  sub_8771A0("efflog", sub_6CDF90);
  sub_8771A0("renderlog", sub_6CDFF0);
  sub_8771A0("goto", sub_6CE080);
  sub_8771A0("supermangoto", sub_6CE080);
  sub_8771A0("supermanyinshen", sub_6CE230);
  sub_8771A0("supermanfast", sub_6CE380);
  sub_8771A0("supermanlevelup", sub_6CE4D0);
  sub_8771A0("supermanchangename", sub_6CE620);
  sub_8771A0("supermancancelbuff", sub_6CE710);
  sub_8771A0("supermancreateshenqi", sub_6CE850);
  sub_8771A0("activelog", sub_6CE000);
  sub_8771A0("enableforbid", sub_6CE020);
  sub_8771A0("skytime", sub_6CE950);
  sub_8771A0("enableeventlog", sub_6CE040);
  sub_8771A0("disableeventlog", sub_6CE060);
  v114 = operator new(0x18u);
  v464 = v114;
  LOBYTE(v660) = 72;
  if ( v114 )
    v115 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v114);
  else
    v115 = 0;
  dword_D35AA0 = v115;
  LOBYTE(v660) = 69;
  v116 = LuaPlus::LuaObject::CreateTable(&v659, &v473, "PlayerShop", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D35AA0, v116);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v473);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D35AA0,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D35AA0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "CreateShop", (int)sub_6D63E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetShopNum", (int)sub_6D68A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumShop", (int)sub_6D6A30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "AskOpenShop", (int)sub_6D6D80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumItem", (int)sub_6D6FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumShopInfo", (int)sub_6D72A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetSelectIndex", (int)sub_6D7640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "RetackItem", (int)sub_6D77C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "InputMoney", (int)sub_6D7C60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "UpStall", (int)sub_6D8070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SetCurSelectPage", (int)sub_6D83E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "DealMoney", (int)sub_6D8530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "ApplyMoney", (int)sub_6D89D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "InfoMoney", (int)sub_6D8FE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetStallNum", (int)sub_6D8FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "BuyItem", (int)sub_6D9130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "IsSelectOnSale", (int)sub_6D93A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "DownSale", (int)sub_6D9530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "ClearSelect", (int)sub_6D9A60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetMoney", (int)sub_6D9B90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetSaleType", (int)sub_6DA000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetCommercialFactor", (int)sub_6DA140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetShopInfo", (int)sub_6DA1B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "IsOpenStall", (int)sub_6DA640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "OpenStall", (int)sub_6DA7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "AskStallData", (int)sub_6DA920, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "UIIndexToLogicIndex", (int)sub_6DAB50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumPet", (int)sub_6DAD00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SetSelectPet", (int)sub_6DB0E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetCanOpenShopType", (int)sub_6DB140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetCreateType", (int)sub_6DB180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SetCurSelectPetIndex", (int)sub_6DB1C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetObjPrice", (int)sub_6DB350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "Modify", (int)sub_6DB620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetObjName", (int)sub_6DBE40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "ViewPetDesc", (int)sub_6DC3B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "ClearSelectPos", (int)sub_6DC530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "Transfer", (int)sub_6DC650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "IsSaleOut", (int)sub_6DCC50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "BuyShop", (int)sub_6DCDA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "CloseShop", (int)sub_6DCE90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "OpenMessage", (int)sub_6DCFF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetMessageNum", (int)sub_6DD220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetCurPageMessageNum", (int)sub_6DD3C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumMessage", (int)sub_6DD530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "DealFriend", (int)sub_6DD5C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetFriendNum", (int)sub_6DD9A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumFriend", (int)sub_6DD9E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "ChangeShopNum", (int)sub_6DDA60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetNpcId", (int)sub_6DDD00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetSelfPlace", (int)sub_6DDD40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetSelfPlaceNew", (int)sub_6E15D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "FindShop", (int)sub_6DDD80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetCurShopType", (int)sub_6DDFF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "Id2TypeName", (int)sub_6DE180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "ModifySubType", (int)sub_6DE380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumSearchShopIndex", (int)sub_6DE630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "AddFavor", (int)sub_6DE6C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "CloseShopMag", (int)sub_6DE800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetShopListType", (int)sub_6DE820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetMessageType", (int)sub_6DE880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetServerOpen", (int)sub_6E1620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SetServerOpen", (int)sub_6E1670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "OpenSelectRecycleItemDLG", (int)sub_6DE950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetRecycleItemClassCount", (int)sub_6DE8C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumRecycleItemClass", (int)sub_6DE9B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumRecycleItemType", (int)sub_6DEB10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetRecycleItemTypeCount", (int)sub_6DEA80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumRecycleItem", (int)sub_6DEC90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetRecycleItemCount", (int)sub_6DEBD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SendAddRecycleItemMsg", (int)sub_6DEE80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "OpenRecycleShopDLG", (int)sub_6DF060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "EnumRecycleItemAction", (int)sub_6DF270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SendTakeRecItemMsg", (int)sub_6DF4A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SendCancelRecItemMsg", (int)sub_6DF640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SetCurSelShopIdx", (int)sub_6DF7E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetCurSelShopIdx", (int)sub_6DF840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "CancelRecItem", (int)sub_6DF880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetRecycleItem", (int)sub_6DF930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetRecycleShopName", (int)sub_6DFCA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetRecycleShopOwnerName", (int)sub_6DFD60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetRecycleShopOwnerID", (int)sub_6DFE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetRecycleShopIndex", (int)sub_6DFF90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetRecycleShopProfitMoney", (int)sub_6DFF00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SendSellItem2RecycleShopMsg", (int)sub_6E0020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "RecycleShop_EnterSell", (int)sub_6E0220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "OpenRecycleShopDLG2", (int)sub_6E0250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "CancelSellItem2RecycleShop", (int)sub_6E03F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "OpenADDlg", (int)sub_6E07E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SendSetRecycleShopADMsg", (int)sub_6E0480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "CloseChangeTypeMsgBox", (int)sub_6E0840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "RecycleShop_GetShopDesc", (int)sub_6E0860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "CloseRecycleShop", (int)sub_6E0910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetLockStatus", (int)sub_6E0930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetUnlockTime", (int)sub_6E0970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SetLockStatus", (int)sub_6E09B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SetUnlockTime", (int)sub_6E0A10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "PacketSend_Search", (int)sub_6E0A70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetPetPSSearchInfo", (int)sub_6E0C80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetPetPortraitByIndex", (int)sub_6E0DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetPetEraCount", (int)sub_6E0EE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "ShowPSCurPage_PetInfo", (int)sub_6E0FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetItemPSInfo", (int)sub_6E1020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SearchPageBuyItem", (int)sub_6E1190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetSelectStall", (int)sub_6E1450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SetSelectStall", (int)sub_6E1490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "GetSelectPos", (int)sub_6E14F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SetSelectPos", (int)sub_6E1530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "IsCoopertiveList", (int)sub_6E1590, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SetPageItemSelect", (int)sub_6E16D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AA0, "SearchPageMultiBuyItem", (int)sub_6E1760, 0);
  v117 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v392, &unk_D35A9C);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v622, v117);
  LOBYTE(v660) = 73;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v622, (const struct LuaPlus::LuaObject *)dword_D35AA0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "PlayerShop", (struct LuaPlus::LuaObject *)&v622);
  v118 = operator new(0x18u);
  v464 = v118;
  LOBYTE(v660) = 74;
  if ( v118 )
    v119 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v118);
  else
    v119 = 0;
  dword_D2E228 = v119;
  LOBYTE(v660) = 73;
  v120 = LuaPlus::LuaObject::CreateTable(&v659, &v522, "Friend", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2E228, v120);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v522);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2E228,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2E228);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Close", (int)sub_60BE00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "EnumName", (int)sub_60BE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "OpenGrouping", (int)sub_60C820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "OpenMenu", (int)sub_60C060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "OpenGroupListMenu", (int)sub_60C370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "AskTeam", (int)sub_60C5D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "GetHistroyNumber", (int)sub_60CB30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "GetHistroyData", (int)sub_60CBD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "SetCurrentTeam", (int)sub_60D0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "GetCurrentTeam", (int)sub_60D130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "SetCurrentSelect", (int)sub_60D170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "GetCurrentSelect", (int)sub_60D1B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "CallOf", (int)sub_60D1F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "ViewFeel", (int)sub_60D340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "IsMoodInHead", (int)sub_60D3E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "IsPlayerIsFriend", (int)sub_60D440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "InviteTeam", (int)sub_60C700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "GetIMChatNumber", (int)sub_60CDA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "GetIMChatData", (int)sub_60CE40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "IsPlayerIsFriendByGuid", (int)sub_60D500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "IsPlayerIsGoodFriendByGuid", (int)sub_60D600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_GetRelationPositionWithTempFriend", (int)sub_60D710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_GetSpouseGuid", (int)sub_60D870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_IsSpouseInFriendOnline", (int)sub_60D9A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_IsShimenMemberInfoValid", (int)sub_60DC40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_IsSameMasterWithMe", (int)sub_60E230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_GetBrotherNumExceptSpouse", (int)sub_60DA30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_GetOnlineBrotherNumExceptSpouse", (int)sub_60DB30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_GetShimenMemberNumExceptSpouseAndBrother", (int)sub_60DCE0, 0);
  sub_877220(
    (LuaPlus::LuaObject *)dword_D2E228,
    "Lua_GetOnlineShimenMemberNumExceptSpouseAndBrother",
    (int)sub_60DE50,
    0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_GetRecruitNum", (int)sub_60DFD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_GetOnlineRecruitNum", (int)sub_60E0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_CheckZhangZhao", (int)sub_60E300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_GetZhangZhaoCount", (int)sub_60E3F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E228, "Lua_CheckOffLineZhengZhao", (int)sub_60E440, 0);
  v121 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v420, &unk_D2E234);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v624, v121);
  LOBYTE(v660) = 75;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v624, (const struct LuaPlus::LuaObject *)dword_D2E228);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Friend", (struct LuaPlus::LuaObject *)&v624);
  v122 = operator new(0x18u);
  v464 = v122;
  LOBYTE(v660) = 76;
  if ( v122 )
    v123 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v122);
  else
    v123 = 0;
  dword_D2E23C = v123;
  LOBYTE(v660) = 75;
  v124 = LuaPlus::LuaObject::CreateTable(&v659, &v493, "FriendSearcher", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2E23C, v124);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v493);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2E23C,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2E23C);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "ClearFingerList", (int)sub_60E610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "OpenFriendSearch", (int)sub_60E650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "FriendSearchByID", (int)sub_60E680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "FriendSearchByName", (int)sub_60E7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "FriendSearchAdvance", (int)sub_60E920, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "GetFriendPageNumber", (int)sub_60EB70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "GetFriendFromPage", (int)sub_60EBD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "GetFriendNumberInPage", (int)sub_60F520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "ForbidItByNameAndGuid", (int)sub_60F580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "ForbidItByNameAndGuidConfirm", (int)sub_60F740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "ViewPlayerPosInfo", (int)sub_60FAB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "ViewPlayerPosGoTo", (int)sub_60FC00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E23C, "ViewPlayerTeamInfo", (int)sub_60FD50, 0);
  v125 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v370, &unk_D2E238);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v626, v125);
  LOBYTE(v660) = 77;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v626, (const struct LuaPlus::LuaObject *)dword_D2E23C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "FriendSearcher", (struct LuaPlus::LuaObject *)&v626);
  v126 = operator new(0x18u);
  v464 = v126;
  LOBYTE(v660) = 78;
  if ( v126 )
    v127 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v126);
  else
    v127 = 0;
  dword_D2E24C = v127;
  LOBYTE(v660) = 77;
  v128 = LuaPlus::LuaObject::CreateTable(&v659, &v520, "GameProduceLogin", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2E24C, v128);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v520);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetServerAreaCount", (int)sub_610150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetServerAreaName", (int)sub_6101A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetServerAreaDis", (int)sub_610230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetServerAreaRecommendLevel", (int)sub_6102C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetAreaLoginServerCount", (int)sub_610360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SetPingServer", (int)sub_610C80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SetCurrentServerPage", (int)sub_610D00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetAreaLoginServerInfo", (int)sub_610410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetAreaLoginServerDelay", (int)sub_610DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetSelectLoginServerDelay", (int)sub_610EC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetIsFluencyServer", (int)sub_611050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SetLoginServerKeyword", (int)sub_610640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetKeywordLoginServerInfo", (int)sub_610740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "LoadLaunch", (int)sub_610D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "KillLaunchProcess", (int)sub_610D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "OpenURL", (int)sub_611100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "StartAccountReg", (int)sub_611270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "StartQRCode", (int)sub_611280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ExitToSelectServer", (int)sub_611290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SendQueneQuitMsg", (int)sub_6112B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SendQueneRemindMsg", (int)sub_6112C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "EnterRecommendServerSelect", (int)sub_6112A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "CheckAccount", (int)sub_6113C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetMiBaoKey", (int)sub_611760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SetMiBaoValue", (int)sub_6117F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SendMiBaoCheckAccount", (int)sub_611940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ReturnToAccountDlg", (int)sub_611910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "RefreshAccountDlg", (int)sub_612290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "CheckBilling1", (int)sub_611980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "CheckBilling2", (int)sub_6120F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "PassportButNotReg", (int)sub_612100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SelectLoginServer", (int)sub_6109F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ChangeToAccountInputDlgFromSelectRole", (int)sub_6122C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ChangeToCreateRoleDlgFromSelectRole", (int)sub_6122D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetCurSelectRole", (int)sub_6123F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ChangeToSelectRoleDlgFromCreateRole", (int)sub_612430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetRoleCount", (int)sub_612440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetRoleInfo", (int)sub_612480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetRoleUIModleName", (int)sub_6126B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "CreateRole", (int)sub_6126E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "DelRole", (int)sub_612920, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SendEnterGameMsg", (int)sub_612980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SendEnterGameMsg_New", (int)sub_6129E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ExitGame_YesNo", (int)sub_612A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ExitToAccountInput_YesNo", (int)sub_612C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "DelSelRole", (int)sub_612E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "CancelDelRole", (int)sub_612E80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SetCurSelect", (int)sub_612E40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ShowMessageBox", (int)sub_612E90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetAreaServerInfo", (int)sub_610400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "AutoSelLoginServer", (int)sub_610C20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetWomanFaceCount", (int)sub_613110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetManFaceCount", (int)sub_613170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetWomanFaceCountForCreate", (int)sub_6131D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetManFaceCountForCreate", (int)sub_613230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetWomanFaceName", (int)sub_613290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetManFaceName", (int)sub_613340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetFaceName", (int)sub_6133F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SetFaceId", (int)sub_6134D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetFaceModelCount", (int)sub_613580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetFaceModelName", (int)sub_613610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetFaceModelInfo", (int)sub_6136C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SetFaceModelId", (int)sub_613780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetHairModelCount", (int)sub_613810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetHairModelName", (int)sub_6138A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "SetHairModelId", (int)sub_613950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ShowModel", (int)sub_6139E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "CloseNetConnect", (int)sub_613A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetSceneInfoCount", (int)sub_613A60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetSceneInfo", (int)sub_613AF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "EnterNewRoleScene", (int)sub_613C10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "EnterNewRoleScene_New", (int)sub_613E80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetEquipSetCount", (int)sub_6140F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetEquipSetName", (int)sub_614140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ChangeNewRoleEquipSet", (int)sub_6141C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ModelRotBegin", (int)sub_614240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ModelRotEnd", (int)sub_6142C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "MoveToCharacter", (int)sub_614340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "ModelZoom", (int)sub_6143A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "LoginPlayer", (int)sub_614420, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "CheckAccountNoMibao", (int)sub_612260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "AgreeProtocol", (int)sub_614470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetPasswdTelCount", (int)sub_614490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetPasswdTelByIndex", (int)sub_6144F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetPasswdTelLDCodeGroupCount", (int)sub_6145B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetPasswdTelCountByLDCodeGroupIndex", (int)sub_614620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetPasswdTelByGroupIndexAndIndex", (int)sub_6146B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetPasswdTelAreaByGroupIndex", (int)sub_614750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetPasswdTelWeightByArea", (int)sub_614810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GameLoginShowSystemInfo", (int)sub_6148E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetNetProvider", (int)sub_614940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "GetZoneWorldid", (int)sub_614980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E24C, "QuitAndUpdate", (int)sub_6149D0, 0);
  v129 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v418, &unk_C690F0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v628, v129);
  LOBYTE(v660) = 79;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v628, (const struct LuaPlus::LuaObject *)dword_D2E24C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "GameProduceLogin", (struct LuaPlus::LuaObject *)&v628);
  v130 = operator new(0x18u);
  v464 = v130;
  LOBYTE(v660) = 80;
  if ( v130 )
    v131 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v130);
  else
    v131 = 0;
  dword_D2DECC = v131;
  LOBYTE(v660) = 79;
  v132 = LuaPlus::LuaObject::CreateTable(&v659, &v479, "CommisionShop", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DECC, v132);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v479);
  sub_877220((LuaPlus::LuaObject *)dword_D2DECC, "SendOpenCommisionShopMsg", (int)sub_5BCD80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DECC, "EnumItem", (int)sub_5BCD90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DECC, "EnumAction", (int)sub_5BD070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DECC, "GetNpcId", (int)sub_5BD200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DECC, "OpenBuyConfrim", (int)sub_5BD240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DECC, "CloseBuyConfrim", (int)sub_5BD4A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DECC, "OnBuyConfrimed", (int)sub_5BD4C0, 0);
  v133 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v390, &unk_D2DEC8);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v630, v133);
  LOBYTE(v660) = 81;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v630, (const struct LuaPlus::LuaObject *)dword_D2DECC);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "CommisionShop", (struct LuaPlus::LuaObject *)&v630);
  v134 = operator new(0x18u);
  v464 = v134;
  LOBYTE(v660) = 82;
  if ( v134 )
    v135 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v134);
  else
    v135 = 0;
  dword_D31E3C = v135;
  LOBYTE(v660) = 81;
  v136 = LuaPlus::LuaObject::CreateTable(&v659, &v518, "ReturnTool", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31E3C, v136);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v518);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "AskToReturn", (int)sub_664C60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "GetReturnItemCount", (int)sub_664EA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "GetReturnPetCount", (int)sub_664EE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "GetReturnShopCount", (int)sub_664F20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "GetIsReturnAllSubject", (int)sub_59B910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "SetReturnAllSubject", (int)sub_59B960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "GetReturnItemPageTatol", (int)sub_6652C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "GetReturnPetPageTatol", (int)sub_665300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "GetReturnShopPageTatol", (int)sub_665340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "GetNowPageNum", (int)sub_665380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "GetPageInfo", (int)sub_6653C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "EnumReturnItem", (int)sub_664F60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "EnumReturnPet", (int)sub_665120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "EnumReturnShop", (int)sub_6651E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "GetReturnResultCount", (int)sub_6654B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E3C, "EnumReturnResult", (int)sub_665510, 0);
  v137 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v416, &unk_D31E38);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v632, v137);
  LOBYTE(v660) = 83;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v632, (const struct LuaPlus::LuaObject *)dword_D31E3C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "ReturnTool", (struct LuaPlus::LuaObject *)&v632);
  v138 = operator new(0x18u);
  v464 = v138;
  LOBYTE(v660) = 84;
  if ( v138 )
    v139 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v138);
  else
    v139 = 0;
  dword_D33054 = v139;
  LOBYTE(v660) = 83;
  v140 = LuaPlus::LuaObject::CreateTable(&v659, &v491, "GemCarve", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D33054, v140);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v491);
  sub_877220((LuaPlus::LuaObject *)dword_D33054, "GetGemCarveInfo", (int)sub_698D10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33054, "UpdateProductAction", (int)sub_698E40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33054, "CarveItem", (int)sub_699070, 0);
  v141 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v376, &unk_C714D4);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v634, v141);
  LOBYTE(v660) = 85;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v634, (const struct LuaPlus::LuaObject *)dword_D33054);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "GemCarve", (struct LuaPlus::LuaObject *)&v634);
  v142 = operator new(0x18u);
  v464 = v142;
  LOBYTE(v660) = 86;
  if ( v142 )
    v143 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v142);
  else
    v143 = 0;
  dword_D3305C = v143;
  LOBYTE(v660) = 85;
  v144 = LuaPlus::LuaObject::CreateTable(&v659, &v516, "GemMelting", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D3305C, v144);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v516);
  sub_877220((LuaPlus::LuaObject *)dword_D3305C, "GetGemMeltingInfo", (int)sub_699080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D3305C, "UpdateProductAction", (int)sub_6991D0, 0);
  v145 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v414, &unk_C7176C);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v636, v145);
  LOBYTE(v660) = 87;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v636, (const struct LuaPlus::LuaObject *)dword_D3305C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "GemMelting", (struct LuaPlus::LuaObject *)&v636);
  v146 = operator new(0x18u);
  v464 = v146;
  LOBYTE(v660) = 88;
  if ( v146 )
    v147 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v146);
  else
    v147 = 0;
  dword_D31E4C = v147;
  LOBYTE(v660) = 87;
  v148 = LuaPlus::LuaObject::CreateTable(&v659, &v469, "ShenqiUpgrade", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31E4C, v148);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v469);
  sub_877220((LuaPlus::LuaObject *)dword_D31E4C, "GetShenqiUpgradeInfo", (int)sub_665C10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E4C, "GetShenqiUpMaterialKind", (int)sub_665D80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E4C, "GetShenqiUpMaterial", (int)sub_665E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E4C, "GetShenqiLevelUpInfo", (int)sub_6660B0, 0);
  v149 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v388, &unk_D31E48);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v638, v149);
  LOBYTE(v660) = 89;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v638, (const struct LuaPlus::LuaObject *)dword_D31E4C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "ShenqiUpgrade", (struct LuaPlus::LuaObject *)&v638);
  v150 = operator new(0x18u);
  v464 = v150;
  LOBYTE(v660) = 90;
  if ( v150 )
    v151 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v150);
  else
    v151 = 0;
  dword_D31CFC = v151;
  LOBYTE(v660) = 89;
  v152 = LuaPlus::LuaObject::CreateTable(&v659, &v514, "PetEquipSuitUp", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31CFC, v152);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v514);
  sub_877220((LuaPlus::LuaObject *)dword_D31CFC, "GetPetEquipUpProductInfo", (int)sub_64E7E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31CFC, "UpdateProductAction", (int)sub_64EAB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31CFC, "GetPetEquipUpMaterial", (int)sub_64ED80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31CFC, "GetPetEquip5LevelupMark", (int)sub_64F010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31CFC, "SendSuitUpConfirm", (int)sub_64F110, 0);
  v153 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v412, &unk_C6BA94);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v640, v153);
  LOBYTE(v660) = 91;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v640, (const struct LuaPlus::LuaObject *)dword_D31CFC);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "PetEquipSuitUp", (struct LuaPlus::LuaObject *)&v640);
  v154 = operator new(0x18u);
  v464 = v154;
  LOBYTE(v660) = 92;
  if ( v154 )
    v155 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v154);
  else
    v155 = 0;
  dword_D31C70 = v155;
  LOBYTE(v660) = 91;
  v156 = LuaPlus::LuaObject::CreateTable(&v659, &v489, "PetEquipSuitDepart", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31C70, v156);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v489);
  sub_877220((LuaPlus::LuaObject *)dword_D31C70, "GetPetEquipDepartInfo", (int)sub_64E380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31C70, "SetPetEquipDepartFunc", (int)sub_64E530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31C70, "ConfirmDepart", (int)sub_64E710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31C70, "ShowConfirm", (int)sub_64E680, 0);
  v157 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v461, &unk_D31C78);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v642, v157);
  LOBYTE(v660) = 93;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v642, (const struct LuaPlus::LuaObject *)dword_D31C70);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "PetEquipSuitDepart", (struct LuaPlus::LuaObject *)&v642);
  v158 = operator new(0x18u);
  v464 = v158;
  LOBYTE(v660) = 94;
  if ( v158 )
    v159 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v158);
  else
    v159 = 0;
  dword_D32F98 = v159;
  LOBYTE(v660) = 93;
  v160 = LuaPlus::LuaObject::CreateTable(&v659, &v512, "DressReplaceColor", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32F98, v160);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v512);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "DressCanPaint", (int)sub_695C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "DressCanWash", (int)sub_695D10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "OpenDressPaintFitting", (int)sub_695E40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "FittingOnDress", (int)sub_695EE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "RestoreDressPaintFitting", (int)sub_696500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "EnableDressPaintTracing", (int)sub_696690, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "GetDressVisualInfo", (int)sub_6966C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "GetDressVisualIndex", (int)sub_696960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "DressOpenDressJian", (int)sub_696B00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "GetDressDesc", (int)sub_696B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "FittingOnDressByDressJian", (int)sub_696DB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "ConditionCheck", (int)sub_696FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "GetDressVisualID", (int)sub_697350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "StoreDressType", (int)sub_697450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "StoreDressByIndex", (int)sub_6974C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "DressIsCanColour", (int)sub_697520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "GetDressInfoByID", (int)sub_6975F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "FittingOnDressByYuanBaoShop", (int)sub_696EC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "FeiyuOnDress", (int)sub_697760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "FeiyuOnNewDress", (int)sub_697BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32F98, "RestoreFeiyuDressPaint", (int)sub_6980B0, 0);
  v161 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v459, &unk_D32FA0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v644, v161);
  LOBYTE(v660) = 95;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v644, (const struct LuaPlus::LuaObject *)dword_D32F98);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "DressReplaceColor", (struct LuaPlus::LuaObject *)&v644);
  v162 = operator new(0x18u);
  v464 = v162;
  LOBYTE(v660) = 96;
  if ( v162 )
    v163 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v162);
  else
    v163 = 0;
  dword_D32E58 = v163;
  LOBYTE(v660) = 95;
  v164 = LuaPlus::LuaObject::CreateTable(&v659, &v477, "DressEnchasing", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32E58, v164);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v477);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "Dress_ComposeShowInfo", (int)sub_690CC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "Dress_PlayUISoundFuncNew", (int)sub_691260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "Do_Dress_SeparateGem", (int)sub_691280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "Get_Dress_Gem_Level", (int)sub_6913E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "OpenDressEnchaseFitting", (int)sub_691500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "FittingOnDress", (int)sub_6915C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "RestoreDressEnchaseFitting", (int)sub_691E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "EnableDressEnchasePreview", (int)sub_692000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "Dress_EnchaseShowInfo", (int)sub_692030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "GetDressGemType", (int)sub_692100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "Lua_FittingOnDressTransfer", (int)sub_692570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "Lua_OpenDressTransferFitting", (int)sub_692240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "Lua_FittingOnDressTransferOver", (int)sub_692B50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "Lua_DressTransferBindConfirmed", (int)sub_692B70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E58, "FittingOnDressNew", (int)sub_692B90, 0);
  v165 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v457, &unk_D32E60);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v646, v165);
  LOBYTE(v660) = 97;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v646, (const struct LuaPlus::LuaObject *)dword_D32E58);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "DressEnchasing", (struct LuaPlus::LuaObject *)&v646);
  v166 = operator new(0x18u);
  v464 = v166;
  LOBYTE(v660) = 98;
  if ( v166 )
    v167 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v166);
  else
    v167 = 0;
  dword_D32EF8 = v167;
  LOBYTE(v660) = 97;
  v168 = LuaPlus::LuaObject::CreateTable(&v659, &v510, "DressGem", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32EF8, v168);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v510);
  sub_877220((LuaPlus::LuaObject *)dword_D32EF8, "GetIndexIDByProperty", (int)sub_6946D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32EF8, "GemFittingOnDress", (int)sub_693AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32EF8, "RestoreDressGemFitting", (int)sub_694540, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32EF8, "GemFittingOnOrigDress", (int)sub_694B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32EF8, "GetCountByDressGemType", (int)sub_694A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32EF8, "GetGemName", (int)sub_695190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32EF8, "GetSameProperty", (int)sub_6953E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32EF8, "GetGemQuality", (int)sub_695820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32EF8, "GetItemNameByProperty", (int)sub_6947C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32EF8, "IsGemOnDressByType", (int)sub_695A50, 0);
  v169 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v455, &unk_D32F00);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v599, v169);
  LOBYTE(v660) = 99;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v599, (const struct LuaPlus::LuaObject *)dword_D32EF8);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "DressGem", (struct LuaPlus::LuaObject *)&v599);
  v170 = operator new(0x18u);
  v464 = v170;
  LOBYTE(v660) = 100;
  if ( v170 )
    v171 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v170);
  else
    v171 = 0;
  dword_D2D8CC = v171;
  LOBYTE(v660) = 99;
  v172 = LuaPlus::LuaObject::CreateTable(&v659, &v487, "TeamBoardDataPool", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2D8CC, v172);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v487);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2D8CC,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2D8CC);
  sub_877220((LuaPlus::LuaObject *)dword_D2D8CC, "GetInfoByPos", (int)sub_538DB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D8CC, "GetTickCount", (int)sub_5390C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D8CC, "SendTeamSeekInfo", (int)sub_539100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D8CC, "SendUserSeekInfo", (int)sub_539410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D8CC, "RequestTeamBoardList", (int)sub_539980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D8CC, "ModifyInfo", (int)sub_539640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D8CC, "DelInfo", (int)sub_539B20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D8CC, "RequestTeam", (int)sub_539D10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D8CC, "ApplyTeam", (int)sub_539F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D8CC, "GetCharNameByRowID", (int)sub_53A0D0, 0);
  v173 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v449, &unk_C4BC98);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v555, v173);
  LOBYTE(v660) = 101;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v555, (const struct LuaPlus::LuaObject *)dword_D2D8CC);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "TeamBoardDataPool", (struct LuaPlus::LuaObject *)&v555);
  v174 = operator new(0x18u);
  v464 = v174;
  LOBYTE(v660) = 102;
  if ( v174 )
    v175 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v174);
  else
    v175 = 0;
  dword_D329B0 = v175;
  LOBYTE(v660) = 101;
  v176 = LuaPlus::LuaObject::CreateTable(&v659, &v508, "Match", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D329B0, v176);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v508);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D329B0,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D329B0);
  sub_877220((LuaPlus::LuaObject *)dword_D329B0, "OpenHuaShanGRMatchScoreMultiTable", (int)sub_686610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D329B0, "CloseHuaShanGRMatchScoreMultiTable", (int)sub_686630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D329B0, "GetHuaShanGRMatchScore", (int)sub_686650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D329B0, "ClearHuaShanGRMatchScore", (int)sub_686850, 0);
  v177 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v447, &unk_D329B8);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v601, v177);
  LOBYTE(v660) = 103;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v601, (const struct LuaPlus::LuaObject *)dword_D329B0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Match", (struct LuaPlus::LuaObject *)&v601);
  v178 = operator new(0x18u);
  v464 = v178;
  LOBYTE(v660) = 104;
  if ( v178 )
    v179 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v178);
  else
    v179 = 0;
  dword_D31F14 = v179;
  LOBYTE(v660) = 103;
  v180 = LuaPlus::LuaObject::CreateTable(&v659, &v550, "YiGuiTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31F14, v180);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v550);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31F14,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31F14);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "GetYiGuiSize", (int)sub_672D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "EnumItem", (int)sub_672D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "SetShowDress", (int)sub_672EC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "EquipDressAskBind", (int)sub_673160, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "EquipDressWithoutAskBind", (int)sub_6731D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "GetYiGuiMoveFromIndex", (int)sub_673230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "GetYiGuiMoveToIndex", (int)sub_673280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "ResetYiGuiMoveFlag", (int)sub_6732D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "EnumItemName", (int)sub_673300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "GetYiGuiNpcID", (int)sub_673630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "CloseYiGui", (int)sub_673680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "PlayDressAction", (int)sub_6736A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "SetChangeSexNewModle", (int)sub_673730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "GetWeaponYiGuiSize", (int)sub_673A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "EnumWeaponItem", (int)sub_673A90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "GetWeaponYiGuiMoveFromIndex", (int)sub_673BE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "GetWeaponYiGuiMoveToIndex", (int)sub_673C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "ResetWeaponYiGuiMoveFlag", (int)sub_673C80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "SetShowWeapon", (int)sub_673CB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "WeaponDressAskBind", (int)sub_673FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "WeaponDressWithoutAskBind", (int)sub_674010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "ClearShowWeapon", (int)sub_674070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "ClearShowDressByIndex", (int)sub_6741D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "DressAllAskBind", (int)sub_6742A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F14, "DressAllWithoutAskBind", (int)sub_674340, 0);
  v181 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v445, &unk_D31F10);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v577, v181);
  LOBYTE(v660) = 105;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v577, (const struct LuaPlus::LuaObject *)dword_D31F14);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "YiGui", (struct LuaPlus::LuaObject *)&v577);
  v182 = operator new(0x18u);
  v464 = v182;
  LOBYTE(v660) = 106;
  if ( v182 )
    v183 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v182);
  else
    v183 = 0;
  dword_D31E24 = v183;
  LOBYTE(v660) = 105;
  v184 = LuaPlus::LuaObject::CreateTable(&v659, &v549, "Raid", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31E24, v184);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v549);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31E24,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31E24);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "OpenSquadMemWindowByIdx", (int)sub_661540, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "CloseSquadMemWindowByGUID", (int)sub_661670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "OpenRaidSquadWindowByIdx", (int)sub_661740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "CloseRaidSquadWindowByIdx", (int)sub_661AF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "IsRaidSquadWindowShow", (int)sub_661BE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "ClearApplicant", (int)sub_661C70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "EraseApplicantByIdx", (int)sub_661CA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetApplicantCount", (int)sub_661D30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetApplicantUIModelNameByIdx", (int)sub_661D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetApplyMemberInfoByIdx", (int)sub_661E00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetInvitationCount", (int)sub_662120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetInvitationByIdx", (int)sub_662170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMemberBufInfoByIdx", (int)sub_662240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMemberBufNumByIdx", (int)sub_662380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMemberBufPriorityByIdx", (int)sub_662450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMemberDetailByIdx", (int)sub_6625A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMemberGUIDByIdx", (int)sub_662B40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMemberInfoByIdx", (int)sub_662C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMemberNameByGUID", (int)sub_663090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMemCount", (int)sub_6631A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "IsMemberInSceneByIdx", (int)sub_6631E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "SelectAsTargetByIdx", (int)sub_6632A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "SetModelLookByIdx", (int)sub_6633D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "SetModelHeadLookByIdx", (int)sub_6634E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "ShowMemberContMenu", (int)sub_6635F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "ExchangeMemberPosition", (int)sub_664450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMySquadMemIdxByUIIdx", (int)sub_6647D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMySquadMemCount", (int)sub_664910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "GetMemberIndexByGUID", (int)sub_664960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "IsLeaderByIdx", (int)sub_664AA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E24, "ConfirmShowAllSquad", (int)sub_664BC0, 0);
  v185 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v443, &unk_D31E20);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v603, v185);
  LOBYTE(v660) = 107;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v603, (const struct LuaPlus::LuaObject *)dword_D31E24);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Raid", (struct LuaPlus::LuaObject *)&v603);
  v186 = operator new(0x18u);
  v464 = v186;
  LOBYTE(v660) = 108;
  if ( v186 )
    v187 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v186);
  else
    v187 = 0;
  dword_D31E6C = v187;
  LOBYTE(v660) = 107;
  v188 = LuaPlus::LuaObject::CreateTable(&v659, &v547, "CSongliaoWarData", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31E6C, v188);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v547);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31E6C,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31E6C);
  sub_877220((LuaPlus::LuaObject *)dword_D31E6C, "GetCampScore", (int)sub_6671C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E6C, "CloseSongliaoWarMulti", (int)sub_667220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E6C, "OpenSongliaoWarMulti", (int)sub_667240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E6C, "GetMyScore", (int)sub_667260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E6C, "GetScoreByIndex", (int)sub_6673B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E6C, "ClearSongliaoData", (int)sub_667500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E6C, "GetLiuboEquipInfo", (int)sub_667630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E6C, "GetLiuboEquipStarUpInfo", (int)sub_6677A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E6C, "GetMaxKillNumData", (int)sub_667560, 0);
  v189 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v441, &dword_D31E74);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v565, v189);
  LOBYTE(v660) = 109;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v565, (const struct LuaPlus::LuaObject *)dword_D31E6C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "CSongliaoWarData", (struct LuaPlus::LuaObject *)&v565);
  v190 = operator new(0x18u);
  v464 = v190;
  LOBYTE(v660) = 110;
  if ( v190 )
    v191 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v190);
  else
    v191 = 0;
  dword_D2D878 = v191;
  LOBYTE(v660) = 109;
  v192 = LuaPlus::LuaObject::CreateTable(&v659, &v545, "SnsDataPool", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2D878, v192);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v545);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2D878,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2D878);
  sub_877220((LuaPlus::LuaObject *)dword_D2D878, "RequestSnsList", (int)sub_534B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D878, "GetInfoByPos", (int)sub_534D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D878, "SendShowPacket", (int)sub_534F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D878, "GetTickCount", (int)sub_534EC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D878, "GetCurrDay", (int)sub_535070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D878, "DiffDayCount", (int)sub_535130, 0);
  v193 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v439, &unk_C4B838);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v649, v193);
  LOBYTE(v660) = 111;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v649, (const struct LuaPlus::LuaObject *)dword_D2D878);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "SnsDataPool", (struct LuaPlus::LuaObject *)&v649);
  v194 = operator new(0x18u);
  v464 = v194;
  LOBYTE(v660) = 112;
  if ( v194 )
    v195 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v194);
  else
    v195 = 0;
  dword_D2D770 = v195;
  LOBYTE(v660) = 111;
  v196 = LuaPlus::LuaObject::CreateTable(&v659, &v543, "CGemChangeDataPool", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2D770, v196);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v543);
  sub_877220((LuaPlus::LuaObject *)dword_D2D770, "RequestDestGemList", (int)sub_5221C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D770, "GetSelectItem", (int)sub_522290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D770, "ShowSelectItem", (int)sub_5222F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D770, "UpdateProductAction", (int)sub_522390, 0);
  v197 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v437, &dword_D2D778);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v650, v197);
  LOBYTE(v660) = 113;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v650, (const struct LuaPlus::LuaObject *)dword_D2D770);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "CGemChangeDataPool", (struct LuaPlus::LuaObject *)&v650);
  v198 = operator new(0x18u);
  v464 = v198;
  LOBYTE(v660) = 114;
  if ( v198 )
    v199 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v198);
  else
    v199 = 0;
  dword_D31F28 = v199;
  LOBYTE(v660) = 113;
  v200 = LuaPlus::LuaObject::CreateTable(&v659, &v541, "Achievement", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31F28, v200);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v541);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "OpenAchvWindow", (int)sub_6744A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetTotalAchvScore", (int)sub_674640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetCompletiveAchvScore", (int)sub_6746F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetCompletiveAchvCount", (int)sub_6747F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetCompletiveAchvInfoByIndex", (int)sub_674840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvTypeCount", (int)sub_674A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvTypeIDByIndex", (int)sub_674A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvTypeInfoByID", (int)sub_674B60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvSubTypeInfoByIndex", (int)sub_674C70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "InitCompletiveAchvListInType", (int)sub_674DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "ClearCompletiveAchvListInType", (int)sub_674F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetCompletiveAchvIDByIndexInType", (int)sub_674F50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvStatusByID", (int)sub_674FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvCount", (int)sub_675090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvInfoByIndex", (int)sub_675110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvInfoByID", (int)sub_6752D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvDateByID", (int)sub_675470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetSubCondCountByID", (int)sub_675530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvSubCondInfoByIndex", (int)sub_675600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetTargetInfo", (int)sub_675750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetTargetAchvStatusByID", (int)sub_675830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "SelectCompareTarget", (int)sub_6758D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "ClearCompareTarget", (int)sub_675A20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetAchvProgressByID", (int)sub_675A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetCompletiveAchvCountInType", (int)sub_675BA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31F28, "GetActiveAchvCount", (int)sub_675D40, 0);
  v201 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v435, &unk_D31F30);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v605, v201);
  LOBYTE(v660) = 115;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v605, (const struct LuaPlus::LuaObject *)dword_D31F28);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Achievement", (struct LuaPlus::LuaObject *)&v605);
  v202 = operator new(0x18u);
  v464 = v202;
  LOBYTE(v660) = 116;
  if ( v202 )
    v203 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v202);
  else
    v203 = 0;
  dword_D32840 = v203;
  LOBYTE(v660) = 115;
  v204 = LuaPlus::LuaObject::CreateTable(&v659, &v539, "WGAch", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32840, v204);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v539);
  sub_877220((LuaPlus::LuaObject *)dword_D32840, "OpenCJ", (int)sub_677700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32840, "OpenShop", (int)sub_677720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32840, "GetCfgByLv", (int)sub_677740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32840, "GetCJMaxCur", (int)sub_677C90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32840, "GetMaxVal", (int)sub_677E20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32840, "GetShopByLv", (int)sub_677EC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32840, "GetLvScore", (int)sub_6781A0, 0);
  v205 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v433, &unk_D32848);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v579, v205);
  LOBYTE(v660) = 117;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v579, (const struct LuaPlus::LuaObject *)dword_D32840);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "WGAch", (struct LuaPlus::LuaObject *)&v579);
  v206 = operator new(0x18u);
  v464 = v206;
  LOBYTE(v660) = 118;
  if ( v206 )
    v207 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v206);
  else
    v207 = 0;
  dword_D2D674 = v207;
  LOBYTE(v660) = 117;
  v208 = LuaPlus::LuaObject::CreateTable(&v659, &v537, "SnsGame", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2D674, v208);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v537);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2D674,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2D674);
  sub_877220((LuaPlus::LuaObject *)dword_D2D674, "OpenSnsGame", (int)sub_51BBC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D674, "GetUIData", (int)sub_51BE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D674, "DoPray", (int)sub_51C200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D674, "TakePrize", (int)sub_51C350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2D674, "SetSnsGameModel", (int)sub_51C3F0, 0);
  v209 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v431, &dword_C49D50);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v607, v209);
  LOBYTE(v660) = 119;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v607, (const struct LuaPlus::LuaObject *)dword_D2D674);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "SnsGame", (struct LuaPlus::LuaObject *)&v607);
  v210 = operator new(0x18u);
  v464 = v210;
  LOBYTE(v660) = 120;
  if ( v210 )
    v211 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v210);
  else
    v211 = 0;
  dword_D31ED0 = v211;
  LOBYTE(v660) = 119;
  v212 = LuaPlus::LuaObject::CreateTable(&v659, &v535, "Transfiguration", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31ED0, v212);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v535);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED0, "GetTransfigeActionItemCount", (int)sub_670D50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED0, "EnumTransfigeAction", (int)sub_670A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED0, "TransfigeActionCanbeCancel", (int)sub_670D00, 0);
  v213 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v429, &unk_D31ECC);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v651, v213);
  LOBYTE(v660) = 121;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v651, (const struct LuaPlus::LuaObject *)dword_D31ED0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Transfiguration", (struct LuaPlus::LuaObject *)&v651);
  v214 = operator new(0x18u);
  v464 = v214;
  LOBYTE(v660) = 122;
  if ( v214 )
    v215 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v214);
  else
    v215 = 0;
  dword_D31A18 = v215;
  LOBYTE(v660) = 121;
  v216 = LuaPlus::LuaObject::CreateTable(&v659, &v533, "MailSystem", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31A18, v216);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v533);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31A18,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31A18);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "CloseSendNewMail", (int)sub_629AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "WriteUserName", (int)sub_629BA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "WriteUserGUID", (int)sub_629C90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "WriteUserTitle", (int)sub_629D40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "WriteUserContex", (int)sub_629EB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "WriteUserMoney", (int)sub_629FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "WritePetName", (int)sub_62A060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "WritePetGUID", (int)sub_62A150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "ReadSendMail", (int)sub_62A220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "SendMailItem", (int)sub_62A620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "AskMaiItemInfo", (int)sub_62A800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "GetAcceptInfo", (int)sub_62A9B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "GetMailCount", (int)sub_62ABC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "AskMailBrowseInfo", (int)sub_62A890, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "SendPresentMail", (int)sub_62AC70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "ShowMailPetInfo", (int)sub_62B070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "RemoveMailIndex", (int)sub_62B1E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "ReceiveItem", (int)sub_62B0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "SetMailCount", (int)sub_62AC10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "ReplyMail", (int)sub_62B3C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "WriteUserReqMoney", (int)sub_62A000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "GetNPCServerID", (int)sub_62B570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "RemoveMail", (int)sub_62B600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "ReadBagIndex", (int)sub_62B720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "MailCharge", (int)sub_62B7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "FilterSpecialChar", (int)sub_62B810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "CleanMailAccessory", (int)sub_62B8B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "GetMailListCreateTime", (int)sub_62B8E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A18, "CheckZoneWordID", (int)sub_62BB20, 0);
  v217 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v427, &unk_D31A14);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v559, v217);
  LOBYTE(v660) = 123;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v559, (const struct LuaPlus::LuaObject *)dword_D31A18);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "MailSystem", (struct LuaPlus::LuaObject *)&v559);
  v218 = operator new(0x18u);
  v464 = v218;
  LOBYTE(v660) = 124;
  if ( v218 )
    v219 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v218);
  else
    v219 = 0;
  dword_D34644 = v219;
  LOBYTE(v660) = 123;
  v220 = LuaPlus::LuaObject::CreateTable(&v659, &v531, "KVKInterface", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D34644, v220);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v531);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D34644,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D34644);
  sub_877220((LuaPlus::LuaObject *)dword_D34644, "IsInKVKServer", (int)sub_6CD7E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34644, "GetKVKExchangeMode", (int)sub_6CD880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34644, "IsKvKRebuildLimitServer", (int)sub_6CD8D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34644, "IsEnableGuildLeagueInKServer", (int)sub_6CD950, 0);
  v221 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v425, &unk_D34640);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v609, v221);
  LOBYTE(v660) = 125;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v609, (const struct LuaPlus::LuaObject *)dword_D34644);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "KVKInterface", (struct LuaPlus::LuaObject *)&v609);
  v222 = operator new(0x18u);
  v464 = v222;
  LOBYTE(v660) = 126;
  if ( v222 )
    v223 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v222);
  else
    v223 = 0;
  dword_D36F48 = v223;
  LOBYTE(v660) = 125;
  v224 = LuaPlus::LuaObject::CreateTable(&v659, &v529, "ZhanTuanInterface", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D36F48, v224);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v529);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D36F48,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D36F48);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetZhanTuanInfo", (int)sub_743B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "ModifyBeforeZhanTuan", (int)sub_743C80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "ModifyZhanTuan", (int)sub_743E20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetLocalZhanTuanInfo", (int)sub_744090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetMembersInfo", (int)sub_744680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetZhanTuanListMenPaiCount", (int)sub_744420, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "IsZhanTuanMember", (int)sub_7449A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetMenberOrder", (int)sub_744AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "ShowInfoWindow", (int)sub_7459D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "RequestZhanTuanOwnRank", (int)sub_745B10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "RequestZhanTuanRankPage", (int)sub_745BB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetZhanTuanRankPage", (int)sub_745C90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "RequestZhanTuanRankInfo", (int)sub_7460C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetZhanTuanRankInfo", (int)sub_7461C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetZhanTuanByGUID", (int)sub_746F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "WeekReward", (int)sub_747060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetAccount", (int)sub_7471E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "CanWatch", (int)sub_7472A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "RequestZhanTuanWatch", (int)sub_747300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetZCYuanBaoAmount", (int)sub_7473D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "SaveZCYuanBao", (int)sub_747490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "TakeOutZCYuanBao", (int)sub_7475B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "IsFinalCompetitor", (int)sub_7476D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "WeddingDaySetClose", (int)sub_747710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "SetMarryDateWaitConfirm", (int)sub_747730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "FriendMaritalRelations", (int)sub_7477A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetConvertUT", (int)sub_747880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetDaysInMonth", (int)sub_747A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "GetGivenDWORDTime", (int)sub_747BB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F48, "AskInviteAddTuan", (int)sub_745A70, 0);
  v225 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v423, &dword_D36F50);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v581, v225);
  LOBYTE(v660) = 127;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v581, (const struct LuaPlus::LuaObject *)dword_D36F48);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "ZhanTuanInterface", (struct LuaPlus::LuaObject *)&v581);
  v226 = operator new(0x18u);
  v464 = v226;
  LOBYTE(v660) = -128;
  if ( v226 )
    v227 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v226);
  else
    v227 = 0;
  dword_D2E2D8 = v227;
  LOBYTE(v660) = 127;
  v228 = LuaPlus::LuaObject::CreateTable(&v659, &v527, "KCity", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2E2D8, v228);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v527);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2E2D8,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2E2D8);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "GetKCityInfo", (int)sub_61A5E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "AskKCityData", (int)sub_61A620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "AskKCityBlackList", (int)sub_61A660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "AddClanBlackList", (int)sub_61A6A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "DelClanBlackList", (int)sub_61A6B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "AddHumanBlackList", (int)sub_61A6C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "DelHumanBlackList", (int)sub_61A6D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "DoSaleTicket", (int)sub_61A700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "DoOpenSalary", (int)sub_61A740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "AskKCityList", (int)sub_61A800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "OpenDetailCityInfo", (int)sub_61A810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "OpenDetailFubenInfo", (int)sub_61A820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "OpenClanInfo", (int)sub_61A830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "OpenSaleTicketUI", (int)sub_61A840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "OpenSetSalaryUI", (int)sub_61A850, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "UpdateProductAction", (int)sub_61A860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "AskClanListForBlackList", (int)sub_61A6F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "CanAddToBlackList", (int)sub_61A6E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "DoLevelUp", (int)sub_61A780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "GetBlackClan", (int)sub_61A8A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "GetBlackHuman", (int)sub_61A8F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "AuthorityConfirm", (int)sub_61A940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "EnumKCityShop", (int)sub_61A9A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "GetKCityShopInfo", (int)sub_61A9E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "DoKCityShop", (int)sub_61AA20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E2D8, "DoExChangeGTC", (int)sub_61A7C0, 0);
  v229 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v421, &word_D2E2E0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v611, v229);
  LOBYTE(v660) = -127;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v611, (const struct LuaPlus::LuaObject *)dword_D2E2D8);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "KCity", (struct LuaPlus::LuaObject *)&v611);
  v230 = operator new(0x18u);
  v464 = v230;
  LOBYTE(v660) = -126;
  if ( v230 )
    v231 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v230);
  else
    v231 = 0;
  dword_D32CB0 = v231;
  LOBYTE(v660) = -127;
  v232 = LuaPlus::LuaObject::CreateTable(&v659, &v525, "ClanTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32CB0, v232);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v525);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D32CB0,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D32CB0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ExpelMem", (int)sub_68E2B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "JoinClan", (int)sub_68E260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "LeaveClan", (int)sub_68E2A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ClanDemise", (int)sub_68E2F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "CreateClan", (int)sub_68E1E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ClanBetray", (int)sub_68E330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "Appointment", (int)sub_68E220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "AskClanList", (int)sub_68E5C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "AcceptInvite", (int)sub_68E370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "RejectInvite", (int)sub_68E3B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "Show_PopMemu", (int)sub_68E190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanListNum", (int)sub_68E600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ModifyClanMotto", (int)sub_68E560, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ApplyToJoinClan", (int)sub_68E520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetSelfClanInfo", (int)sub_68E4A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetCurPageIndex", (int)sub_68E660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanMemberIdx", (int)sub_68E5A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanMembersNum", (int)sub_68E440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanTraineeIdx", (int)sub_68E5B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanMembersInfo", (int)sub_68E450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "AskClanMembersInfo", (int)sub_68E430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanSelfMemIndex", (int)sub_68E490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetTotalClanListNum", (int)sub_68E650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "InviteOtherToJoinClan", (int)sub_68E4E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetSelfClanDetailInfo", (int)sub_68E3F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ToggleConfirmLeaveClan", (int)sub_68E180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanInfoFromClanList", (int)sub_68E610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ToggleConfirmClanDemise", (int)sub_68E140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ToggleConfirmClanExpelMem", (int)sub_68E100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ToggleClanDetailInfoWindow", (int)sub_68E0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ToogleClanGuildChooseWindow", (int)sub_68E1D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "PrepareClanMembersInfomation", (int)sub_68E7F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetThreeCityInfo", (int)sub_68E670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanOfficerList", (int)sub_68E680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetLookupClanDetailInfo", (int)sub_68E6C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "PrepareOfficerList", (int)sub_68E700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanOfficerIdx", (int)sub_68E710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanOfficerNum", (int)sub_68E720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "GetClanOfficerInfo", (int)sub_68E730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "Officer_Show_PopMemu", (int)sub_68E770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32CB0, "ModifyTankCountLimit", (int)sub_68E7B0, 0);
  v233 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v419, &unk_D32CB8);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v567, v233);
  LOBYTE(v660) = -125;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v567, (const struct LuaPlus::LuaObject *)dword_D32CB0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Clan", (struct LuaPlus::LuaObject *)&v567);
  v234 = operator new(0x18u);
  v464 = v234;
  LOBYTE(v660) = -124;
  if ( v234 )
    v235 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v234);
  else
    v235 = 0;
  dword_D36F34 = v235;
  LOBYTE(v660) = -125;
  v236 = LuaPlus::LuaObject::CreateTable(&v659, &v523, "UnionTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D36F34, v236);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v523);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D36F34,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D36F34);
  sub_877220((LuaPlus::LuaObject *)dword_D36F34, "LeaveUnion", (int)sub_7429A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F34, "RejectUnion", (int)sub_742A20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F34, "CreateUnion", (int)sub_742990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F34, "AcceptUnion", (int)sub_7429E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F34, "AskUnionInfo", (int)sub_742910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F34, "ApplyJoinUnion", (int)sub_742950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F34, "GetUnionClanNum", (int)sub_742A60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F34, "ToggleUnionWindow", (int)sub_7428F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F34, "GetUnionChiefClanIdx", (int)sub_742DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F34, "GetUnionClanInfoByIdx", (int)sub_742AA0, 0);
  v237 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v417, &off_C75920);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v613, v237);
  LOBYTE(v660) = -123;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v613, (const struct LuaPlus::LuaObject *)dword_D36F34);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Union", (struct LuaPlus::LuaObject *)&v613);
  v238 = operator new(0x18u);
  v464 = v238;
  LOBYTE(v660) = -122;
  if ( v238 )
    v239 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v238);
  else
    v239 = 0;
  dword_D35AEC = v239;
  LOBYTE(v660) = -123;
  v240 = LuaPlus::LuaObject::CreateTable(&v659, &v521, "PneumaTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D35AEC, v240);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v521);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D35AEC,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D35AEC);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "EnumPneumaItem", (int)sub_6E2EF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "SmeltPneumaItem", (int)sub_6E3140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "SmeltAllPneumaItem", (int)sub_6E32F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "SmeltAllItem_WithCuijie", (int)sub_6E3480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "ToggleZhenYuanPage", (int)sub_6E3610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaExp", (int)sub_6E3780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaChip", (int)sub_6E3730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetMF", (int)sub_6E37D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "IsMissionAcc", (int)sub_6E3C70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "IsHaveMissionComplete", (int)sub_6E3D00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "TidyBagPneuma", (int)sub_6E3DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaProperty", (int)sub_6E4150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaItemProperty", (int)sub_6E4800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetSmeltBag_SpaceCount", (int)sub_6E4220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "PickPneumaUpToBag", (int)sub_6E42B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "UnWearPneumaToBag", (int)sub_6E43F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "PnuemaLock", (int)sub_6E4620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaCuiJieInfo", (int)sub_6E48D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetNextLevelAddingInfo", (int)sub_6E4AF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetExp_IfSmeltAll", (int)sub_6E4C50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "IsSmeltAll_OverMaxExp", (int)sub_6E4CC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaChipMax", (int)sub_6E4D50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaExpMax", (int)sub_6E4D90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "ToggleTargetZhenYuanPage", (int)sub_6E4DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "SetClientLock", (int)sub_6E4E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaAddingInfo", (int)sub_6E5030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetTargetPneumaAddingInfo", (int)sub_6E5340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetTargetMFAct", (int)sub_6E55F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaSet", (int)sub_6E5680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetTargetPneumaItemProperty", (int)sub_6E57B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "SetPneumaBeforeConvert", (int)sub_6E5B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "SetPneumaAfterConvert", (int)sub_6E5CF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaConvertProperty", (int)sub_6E5880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "SetPneumaBeforeSwitchGold", (int)sub_6E5E00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "SetPneumaAfterSwitchGold", (int)sub_6E5FC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "GetPneumaSwitchGoldProperty", (int)sub_6E60D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "SetPneumaBeforeFenLiGold", (int)sub_6E6360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35AEC, "SetPneumaAfterFenLiGold", (int)sub_6E6480, 0);
  v241 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v415, &off_C746CC);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v583, v241);
  LOBYTE(v660) = -121;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v583, (const struct LuaPlus::LuaObject *)dword_D35AEC);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Pneuma", (struct LuaPlus::LuaObject *)&v583);
  v242 = operator new(0x18u);
  v464 = v242;
  LOBYTE(v660) = -120;
  if ( v242 )
    v243 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v242);
  else
    v243 = 0;
  dword_D33E38 = v243;
  LOBYTE(v660) = -121;
  v244 = LuaPlus::LuaObject::CreateTable(&v659, &v519, "InfantTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D33E38, v244);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v519);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D33E38,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D33E38);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "ToggleInfantPage", (int)sub_6BF470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantCount", (int)sub_6BF520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantMaxCount", (int)sub_6BF560, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantName", (int)sub_6BF5A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantSex", (int)sub_6BF640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantDadName", (int)sub_6BF6F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantMumName", (int)sub_6BF790, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantLevel", (int)sub_6BF830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantExp", (int)sub_6BF990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantCurMaxExp", (int)sub_6BFA50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantFFatherName", (int)sub_6BFF60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantFMotherName", (int)sub_6C0000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantAttr", (int)sub_6C00A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantMaxAttr", (int)sub_6C01A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantMaxAttr_MaxLevel", (int)sub_6C02C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantGUID", (int)sub_6BFC00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "CheckNameString", (int)sub_6BFD00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetMainAttribute", (int)sub_6C0630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetStage", (int)sub_6BF8E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "ChangeInfantName", (int)sub_6C03D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantSkillInfo", (int)sub_6C0710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetRefreshInfantSkillInfo", (int)sub_6C0BC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantSkillValue", (int)sub_6C1130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantRefreshSkillValue", (int)sub_6C1370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetMaxSkillNum", (int)sub_6C1330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "SetInfantModel", (int)sub_6C15A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "ChangeAction_Bantered", (int)sub_6C1640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "ChangeAction_Relax", (int)sub_6C1720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "ChangeAction_OutBadStatus", (int)sub_6C1800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Call_Up", (int)sub_6C18E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "ReCall_Up", (int)sub_6C1B10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetIsFighting", (int)sub_6C1C20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "HandleInfantMenuItem", (int)sub_6C1CE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "SetInfantNewModel", (int)sub_6C2050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroType", (int)sub_6C20F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroLevel", (int)sub_6C2190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroExp", (int)sub_6C2250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetCurMaxHeroExp", (int)sub_6C2310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroConFix", (int)sub_6C2440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroDexFix", (int)sub_6C2570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroHitFix", (int)sub_6C26A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroMissFix", (int)sub_6C27D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroCriticalFix", (int)sub_6C2900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroIceAttackFix", (int)sub_6C2A30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroFireAttackFix", (int)sub_6C2B60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroXuanAttackFix", (int)sub_6C2C90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroPoisonAttackFix", (int)sub_6C2DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "InitHeroObj", (int)sub_6C2EF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "ClearHeroObj", (int)sub_6C2FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "SetHeroModel", (int)sub_6C3010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHeroValueFix", (int)sub_6C3170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantCardValueFix", (int)sub_6C3350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "UseInfantCard", (int)sub_6C35F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetIsPerfectHero", (int)sub_6C3680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetShowHeroCheck", (int)sub_6C37A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "SetShowHeroCheck", (int)sub_6C37F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "SetSpecialObjProperty", (int)sub_6C3C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetDressConvertInfo", (int)sub_6C3D00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantYiguiRealSize", (int)sub_6C3EB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "UpdateInfantYigui", (int)sub_6C3F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantDressVisualById", (int)sub_6C3F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantYiguiItemInfo", (int)sub_6C3FE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "SendInfantYiguiDressUp", (int)sub_6C4310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "SetHairColorBright", (int)sub_6C44F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHairColorBright", (int)sub_6C43D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantHairColorRGBA", (int)sub_6C46C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "MakeRGBAData", (int)sub_6C4810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetHairData", (int)sub_6C4950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantHairStyle", (int)sub_6C4BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantDressPaintData", (int)sub_6C4CC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantDressVisualByItem", (int)sub_6C4F40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantDressRareByItem", (int)sub_6C51A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "SetInfantFittingData", (int)sub_6C5450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantFittingData", (int)sub_6C53D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "ClearInfantFittingData", (int)sub_6C54D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "UpdateVirtualMaterial", (int)sub_6C5530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "SetFittingProperty", (int)sub_6C57C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "ClearFittingProperty", (int)sub_6C5850, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroType", (int)sub_6C6A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroLevel", (int)sub_6C6AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroExp", (int)sub_6C6BA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroConFix", (int)sub_6C6C60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroDexFix", (int)sub_6C6D90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroHitFix", (int)sub_6C6EC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroMissFix", (int)sub_6C6FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroCriticalFix", (int)sub_6C7120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroIceAttackFix", (int)sub_6C7250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroFireAttackFix", (int)sub_6C7380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroXuanAttackFix", (int)sub_6C74B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroPoisonAttackFix", (int)sub_6C75E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_ToggleInfantPage", (int)sub_6C5860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantCount", (int)sub_6C58B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantName", (int)sub_6C58F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantSex", (int)sub_6C5990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantDadName", (int)sub_6C5A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantMumName", (int)sub_6C5AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantLevel", (int)sub_6C5B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetStage", (int)sub_6C5C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantExp", (int)sub_6C5CE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantCurMaxExp", (int)sub_6C5DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantGUID", (int)sub_6C5F40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantFFatherName", (int)sub_6C6040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantFMotherName", (int)sub_6C60E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantAttr", (int)sub_6C6180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantMaxAttr", (int)sub_6C6280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantMaxAttr_MaxLevel", (int)sub_6C63A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetMainAttribute", (int)sub_6C64B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetSkillInfo", (int)sub_6C6590, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_SetInfantModel", (int)sub_6C69A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetHeroValueFix", (int)sub_6C7710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantCardValueFix", (int)sub_6C78F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetIsPerfectHero", (int)sub_6C7B90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Other_GetInfantCardInfo", (int)sub_6C7CA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantName", (int)sub_6C7DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantSex", (int)sub_6C7E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantDadName", (int)sub_6C7EA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantMumName", (int)sub_6C7F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantLevel", (int)sub_6C7F60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetStage", (int)sub_6C7FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantExp", (int)sub_6C8040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantCurMaxExp", (int)sub_6C80C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantGUID", (int)sub_6C8210, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantFFatherName", (int)sub_6C82C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantFMTargetName", (int)sub_6C8320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantAttr", (int)sub_6C8380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantMaxAttr", (int)sub_6C8440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantMaxAttr_MaxLevel", (int)sub_6C8510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetMainAttribute", (int)sub_6C85E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetSkillInfo", (int)sub_6C8670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_SetInfantModel", (int)sub_6C8A60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroType", (int)sub_6C8AA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroLevel", (int)sub_6C8B10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroExp", (int)sub_6C8B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroConFix", (int)sub_6C8C00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroDexFix", (int)sub_6C8CE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroHitFix", (int)sub_6C8DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroMissFix", (int)sub_6C8EA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroCriticalFix", (int)sub_6C8F80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroIceAttackFix", (int)sub_6C9060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroFireAttackFix", (int)sub_6C9140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroXuanAttackFix", (int)sub_6C9220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroPoisonAttackFix", (int)sub_6C9300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetHeroValueFix", (int)sub_6C93E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetInfantCardValueFix", (int)sub_6C9580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "Target_GetIsPerfectHero", (int)sub_6C97E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantCardItemIndex", (int)sub_6C38E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantCardYanDuLevel", (int)sub_6C3A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33E38, "GetInfantCardQuality", (int)sub_6C3B20, 0);
  v245 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v413, &off_C72CDC);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v615, v245);
  LOBYTE(v660) = -119;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v615, (const struct LuaPlus::LuaObject *)dword_D33E38);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "Infant", (struct LuaPlus::LuaObject *)&v615);
  v246 = operator new(0x18u);
  v464 = v246;
  LOBYTE(v660) = -118;
  if ( v246 )
    v247 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v246);
  else
    v247 = 0;
  dword_D32C84 = v247;
  LOBYTE(v660) = -119;
  v248 = LuaPlus::LuaObject::CreateTable(&v659, &v517, "BWDHTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32C84, v248);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v517);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D32C84,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D32C84);
  sub_877220((LuaPlus::LuaObject *)dword_D32C84, "GetCompeMarrySponsorInfo", (int)sub_688C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C84, "GetCompeMarryCurStatus", (int)sub_688DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C84, "GetCompeMarryCurSponsor", (int)sub_688DF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C84, "GetCompeMarryCurLeizhu", (int)sub_688EC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C84, "GetCompeMarryCurTiaozhan", (int)sub_688F90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C84, "SetPlayerWatchPosDirection", (int)sub_689060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C84, "CancelPlayerWatchPosDirection", (int)sub_6892E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C84, "SetSpecialSceneFlag", (int)sub_689330, 0);
  v249 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v411, &off_C6FA4C);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v553, v249);
  LOBYTE(v660) = -117;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v553, (const struct LuaPlus::LuaObject *)dword_D32C84);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "BWDH", (struct LuaPlus::LuaObject *)&v553);
  v250 = operator new(0x18u);
  v464 = v250;
  LOBYTE(v660) = -116;
  if ( v250 )
    v251 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v250);
  else
    v251 = 0;
  dword_D32C8C = v251;
  LOBYTE(v660) = -117;
  v252 = LuaPlus::LuaObject::CreateTable(&v659, &v515, "BWDH2018Table", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32C8C, v252);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v515);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D32C8C,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D32C8C);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetCopySceneBWPlayerInfoByIdx2018", (int)sub_689660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetCopySceneBWFirstKillerType2018", (int)sub_689800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetBWTroopsPK_LeftTimes2018", (int)sub_689530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "SetBMMainTargetByUIIdx2018", (int)sub_689580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetXbwGetRecentSeasonInfo2018", (int)sub_689850, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetXbwDuanweinfo2018", (int)sub_6899B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetXbwSeasonAward2018", (int)sub_689B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetResultData", (int)sub_689DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetCalcBattleScoreAndDuanweiInfoByIdx2018", (int)sub_68A030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetBWTroopsPK_Result_Info2018", (int)sub_68A0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetRankListNum", (int)sub_68A140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetRankListInfoByIndex", (int)sub_68A190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetRankMatchID", (int)sub_68A350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "CanQueryRankingAgain", (int)sub_68A3A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetSelfInfo", (int)sub_68A400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetRankAward", (int)sub_68A5B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "Show_PopMemu", (int)sub_68A740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetMatchId", (int)sub_68B080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetMembersInfo", (int)sub_68B110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetMyUIDirInfo", (int)sub_68B1A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetBWDaiBiShopInfo", (int)sub_68AD40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "EnumBWDaiBiShop", (int)sub_68AAE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetShopItemCount", (int)sub_68B1F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "CreateWTeam", (int)sub_68B2B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetWTeamMemberInfoByIdx", (int)sub_68B570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetDetailWTeamInfo", (int)sub_68B7C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetWTeamMemberPost", (int)sub_68B720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "WTeamOper_Invite", (int)sub_68BA90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "WTeamOper_RetInvite", (int)sub_68BC20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "WTeam_Dismiss", (int)sub_68BEA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "WTeam_KickMember", (int)sub_68BFB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "WTeam_Leave", (int)sub_68C180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "IsWTeamLeader", (int)sub_68C290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "IsWTeamLeaderGuid", (int)sub_68C330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetWTeamMemberCount", (int)sub_68C440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "OpenMenu", (int)sub_68C490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetRankNodeBuildInfo", (int)sub_68C7E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetRankNodeProInfo", (int)sub_68C910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetRankNodeCount", (int)sub_68CA70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "RequsetRankingCharts", (int)sub_68CAC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetRankingStage", (int)sub_68CB60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "RequsetWTeamInfo", (int)sub_68CBB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "RequsetWTeamInfoForGuess", (int)sub_68CCD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetFightPairCount", (int)sub_68CDF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetFightPairFlag", (int)sub_68CF70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetFightPairInfoByIdx", (int)sub_68CE40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetTXbwStage", (int)sub_68CFC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetTXbwCreateWTeamDate", (int)sub_68D100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetTXbwPromotionDate", (int)sub_68D220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetTXbwFinalDate", (int)sub_68D360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "Format_YMD2Str", (int)sub_68D4A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetPlayerGuess", (int)sub_68D610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetFinalDayByIndex", (int)sub_68D710, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetWTeamIDAndNameForGuess", (int)sub_68D860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "IsTeamWin", (int)sub_68DAB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetWTeamNameForGuess", (int)sub_68DC40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C8C, "GetDfsWTeamInfoByIdx", (int)sub_68DD20, 0);
  v253 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v409, &off_C6FD10);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v617, v253);
  LOBYTE(v660) = -115;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v617, (const struct LuaPlus::LuaObject *)dword_D32C8C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "BWDH2018", (struct LuaPlus::LuaObject *)&v617);
  v254 = operator new(0x18u);
  v464 = v254;
  LOBYTE(v660) = -114;
  if ( v254 )
    v255 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v254);
  else
    v255 = 0;
  dword_D32E44 = v255;
  LOBYTE(v660) = -115;
  v256 = LuaPlus::LuaObject::CreateTable(&v659, &v513, "DoubleGemTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32E44, v256);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v513);
  sub_877220((LuaPlus::LuaObject *)dword_D32E44, "GetDoubleGemInfo", (int)sub_690540, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E44, "GetDoubleGemInfobyID", (int)sub_6906C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E44, "UpdateProductAction", (int)sub_690800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E44, "GetGemNamebyID", (int)sub_690A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E44, "IsDoubleGem", (int)sub_690B00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32E44, "IsDoubleGembyID", (int)sub_690BB0, 0);
  v257 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v407, &off_C70784);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v585, v257);
  LOBYTE(v660) = -113;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v585, (const struct LuaPlus::LuaObject *)dword_D32E44);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "DoubleGem", (struct LuaPlus::LuaObject *)&v585);
  v258 = operator new(0x18u);
  v464 = v258;
  LOBYTE(v660) = -112;
  if ( v258 )
    v259 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v258);
  else
    v259 = 0;
  dword_D32C78 = v259;
  LOBYTE(v660) = -113;
  v260 = LuaPlus::LuaObject::CreateTable(&v659, &v511, "BudgetPlanGemTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32C78, v260);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v511);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "IsBudgetPlanGem", (int)sub_687C50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "CheckBudgetPlanGemForDelProtectGoods", (int)sub_687DE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBudgetPlanGemPrice", (int)sub_687F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetRepayGapTimes", (int)sub_687FE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "AskBudgetPlanGemInfo", (int)sub_688030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBudgetPlanGemInfoCount", (int)sub_6880B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBudgetPlanGemInfoPositionType", (int)sub_688100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBudgetPlanGemInfoPositionParm1", (int)sub_688190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBudgetPlanGemInfoPositionParm2", (int)sub_688220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBudgetPlanGemInfoGemIndex", (int)sub_6882B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBudgetPlanGemInfoBuyPrice", (int)sub_688340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBudgetPlanGemInfoDueTime", (int)sub_6883D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBudgetPlanGemInfoPayStage", (int)sub_688460, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "UpdateProductAction", (int)sub_6884F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "IsBudgetPlanGemVild", (int)sub_688800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "BudgetPlanGemDayTimeToYMD", (int)sub_6888A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetServerDayTime", (int)sub_688970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBagItemIsValid", (int)sub_6889C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "GetBagItemDueTime", (int)sub_688AC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32C78, "IsBudgetPlanGemByGemID", (int)sub_687D10, 0);
  v261 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v405, &off_C6F744);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v619, v261);
  LOBYTE(v660) = -111;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v619, (const struct LuaPlus::LuaObject *)dword_D32C78);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "BudgetPlanGem", (struct LuaPlus::LuaObject *)&v619);
  v262 = operator new(0x18u);
  v464 = v262;
  LOBYTE(v660) = -110;
  if ( v262 )
    v263 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v262);
  else
    v263 = 0;
  dword_D2DCD0 = v263;
  LOBYTE(v660) = -111;
  v264 = LuaPlus::LuaObject::CreateTable(&v659, &v509, "ActionSystem", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DCD0, v264);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v509);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DCD0,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DCD0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DCD0, "GetDefineID", (int)sub_59DB40, 0);
  v265 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v403, &unk_D2DCCC);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v569, v265);
  LOBYTE(v660) = -109;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v569, (const struct LuaPlus::LuaObject *)dword_D2DCD0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "ActionSystem", (struct LuaPlus::LuaObject *)&v569);
  v266 = operator new(0x18u);
  v464 = v266;
  LOBYTE(v660) = -108;
  if ( v266 )
    v267 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v266);
  else
    v267 = 0;
  dword_D2DED4 = v267;
  LOBYTE(v660) = -109;
  v268 = LuaPlus::LuaObject::CreateTable(&v659, &v507, "CorpsUI", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DED4, v268);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v507);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DED4,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DED4);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCorpsMemberInfoByIdx", (int)sub_5BD4E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetDetailCorpsInfo", (int)sub_5BD6D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCorpsMemberPosition", (int)sub_5BD630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "CorpsOper_InviteCorps", (int)sub_5BDB60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "CorpsOper_AssignAssist", (int)sub_5BDCE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "CorpsOper_CancelAssist", (int)sub_5BDED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "Corps_HasAssist", (int)sub_5BE0E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "Corps_DismissCorps", (int)sub_5BE130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCorps_DismissCD_State", (int)sub_5BDB10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "IsCorpsLeader", (int)sub_5BE580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "IsCorpsAssist", (int)sub_5BE620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "IsCorpsAssistGuid", (int)sub_5BE6C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCorpsMemberCount", (int)sub_5BE7D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "AskCorpsMemberJoinTeam", (int)sub_5BE820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "Corps_KickCorpsMember", (int)sub_5BE260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "Corps_LeaveCorps", (int)sub_5BE450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCopyScenePlayerInfoByIdx", (int)sub_5BE970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetTwoCorpsNameInCopyScene", (int)sub_5BEB40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetTwoCorpsScoreInCopyScene", (int)sub_5BEBA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCorpsScoreIncCopyScene", (int)sub_5BECA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCorpsScoreDecCopyScene", (int)sub_5BECF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCorpsPK_Result_Info", (int)sub_5BEC20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCorpsPK_LeftTimes", (int)sub_5BED40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCopySceneFirstKillerType", (int)sub_5BED90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetRankingChartsNodeInfo", (int)sub_5BEDE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "CanQueryRankingAgain", (int)sub_5BEF20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "RequsetRankingCharts", (int)sub_5BEF80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetRankingTotalPage", (int)sub_5BF080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetRankingCurPage", (int)sub_5BF0D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "RequsetCorpsInfo", (int)sub_5BF170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetRankingStage", (int)sub_5BF120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "IsCorpsGameOver", (int)sub_5BF260, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "SetMainTargetByUIIdx", (int)sub_5BF2B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "SendPlayerInfoToServer", (int)sub_5BF3A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetFightPairCount", (int)sub_5BF720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetFightPairInfoByIdx", (int)sub_5BF5F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetReliveCorpsNum", (int)sub_5BF770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetReliveCorpName", (int)sub_5BF7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetReliveCorpMemberCount", (int)sub_5BF810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetReliveCorpMemberName", (int)sub_5BF880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetReliveCorpMemberLevel", (int)sub_5BF900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetReliveCorpMemberMenpai", (int)sub_5BF990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetReliveCorpVoteCount", (int)sub_5BFA20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetReliveCorpGUID", (int)sub_5BFA90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GiveOneVoteToCorp", (int)sub_5BFB00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GiveAllVoteToCorp", (int)sub_5BFDE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "VoteToCorpBeSure", (int)sub_5BFFF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "ClearTempCorpInfo", (int)sub_5C02D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetTempCorpGUID", (int)sub_5C02E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetTempVoteNum", (int)sub_5C0320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "SetTempVoteNum", (int)sub_5C0360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCorpLeaderIndex", (int)sub_5C03B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetCorpAssistIndex", (int)sub_5C0420, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "GetFinalCorpsInfoByIdx", (int)sub_5C0490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "SetPlayerWatchPosDirection", (int)sub_5C0570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "CancelPlayerWatchPosDirection", (int)sub_5C0B60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "SetSpecialSceneFlag", (int)sub_5C0BB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetWeekHuoyueNotice", (int)sub_5D0250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetChallengeInfo", (int)sub_5F7700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetChallengeCount", (int)sub_5F78C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "EnterChallengeView", (int)sub_5F7900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskChallengeList", (int)sub_5F7A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_SetMeiLiValue", (int)sub_5F7BE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "Lua_GetMeiLiValue", (int)sub_5F7C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCityWarBaseInfo", (int)sub_5F5C80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCampMenberR", (int)sub_5F5DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetCampMenberB", (int)sub_5F5F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "OpenWuMengMemberList", (int)sub_5F6070, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskWuMengMemberList", (int)sub_5F61B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "AskWuMengBuildingInfo", (int)sub_5F62A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBuidinginfo", (int)sub_5F6330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetResultParam", (int)sub_5F63D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTop3MemberR", (int)sub_5F6460, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetTop3MemberB", (int)sub_5F6600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetResultInfo", (int)sub_5F67A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetOverTime", (int)sub_5F68F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetLeaderName", (int)sub_5F6940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBattleState", (int)sub_5F69B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetBattleState", (int)sub_5F6A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBattleTongChouOtherInfo", (int)sub_5F6A80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBattleTongChouInfoByIndex", (int)sub_5F6BA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetBattleTongChouInfoByIndex", (int)sub_5F6C30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetRefreshType", (int)sub_5F6CD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetRefreshType", (int)sub_5F6D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CleanCityWarInfo", (int)sub_5F6DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "CleanCityWarMemberInfo", (int)sub_5F6DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetResB", (int)sub_5F6F80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetResB", (int)sub_5F6FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetResRobed", (int)sub_5F7040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetResRobed", (int)sub_5F7090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetWarState", (int)sub_5F7100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetWarState", (int)sub_5F7150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBieYeScenePlayerCount", (int)sub_5F71C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "GetBieYeScenePlayerInfo", (int)sub_5F7200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "TickBieYeScenePlayer", (int)sub_5F7340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "IsBieyePlayerListCanRefresh", (int)sub_5F7430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEF4, "SetBieYePlayerSelect", (int)sub_5F74A0, 0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "PutItemToMainmenuBar2",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D680,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaAskSafeCode",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58DAA0,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaSendSafeCode",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58DB20,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_SendRecheckInfo",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58DC50,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "LuaCYJTest",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58D970,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetALLRlBuffNum",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58DE00,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetRlBuffFromTable",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58DE80,
    0);
  LuaPlus::LuaObject::Register(
    (LuaPlus::LuaObject *)&v659,
    "Lua_GetRlBuffNameByID",
    (int (__cdecl *)(struct LuaPlus::LuaState *))sub_58E040,
    0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DED4, "SendPlayerInfoToServer_WOW", (int)sub_5C0C20, 0);
  v269 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v401, &unk_D2DED0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v621, v269);
  LOBYTE(v660) = -107;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v621, (const struct LuaPlus::LuaObject *)dword_D2DED4);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "CorpsUI", (struct LuaPlus::LuaObject *)&v621);
  v270 = operator new(0x18u);
  v464 = v270;
  LOBYTE(v660) = -106;
  if ( v270 )
    v271 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v270);
  else
    v271 = 0;
  dword_D31E40 = v271;
  LOBYTE(v660) = -107;
  v272 = LuaPlus::LuaObject::CreateTable(&v659, &v504, "AccountSafe", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31E40, v272);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v504);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31E40,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31E40);
  sub_877220((LuaPlus::LuaObject *)dword_D31E40, "SendHardWareCheckMsg", (int)sub_665780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E40, "SendAppWareCheckMsg", (int)sub_665880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E40, "SendRequestSafeCodeMsg", (int)sub_665970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E40, "SendLoginSafeCheckMsg", (int)sub_665A20, 0);
  v273 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v399, &unk_D31E44);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v587, v273);
  LOBYTE(v660) = -105;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v587, (const struct LuaPlus::LuaObject *)dword_D31E40);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "AccountSafe", (struct LuaPlus::LuaObject *)&v587);
  v274 = operator new(0x18u);
  v464 = v274;
  LOBYTE(v660) = -104;
  if ( v274 )
    v275 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v274);
  else
    v275 = 0;
  dword_D31EE0 = v275;
  LOBYTE(v660) = -105;
  v276 = LuaPlus::LuaObject::CreateTable(&v659, &v502, "WenDingUI", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31EE0, v276);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v502);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31EE0,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31EE0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "GetCSRankByIdx", (int)sub_671800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "GetShiMenInfoByIdx", (int)sub_671920, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "ClearShiMenInfo", (int)sub_671D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "SetShiMenGongfengByGuid", (int)sub_671E20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "GetShideLevel", (int)sub_671F90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "GetCurShide", (int)sub_671FE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "GetWeekShide", (int)sub_672030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "GetHistoryShide", (int)sub_672080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "UpdateShideShopData", (int)sub_6720D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "GetShideShopItemNum", (int)sub_6722B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "GetShideShopItemLayerNum", (int)sub_6723A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "EnumShideShop", (int)sub_6724B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "GetShideShopInfo", (int)sub_6726B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "DoShideShopBuy", (int)sub_6728E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31EE0, "IsShideShopMultiBuy", (int)sub_672A40, 0);
  v277 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v397, &dword_D31EE4);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v623, v277);
  LOBYTE(v660) = -103;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v623, (const struct LuaPlus::LuaObject *)dword_D31EE0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "WenDingUI", (struct LuaPlus::LuaObject *)&v623);
  v278 = operator new(0x18u);
  v464 = v278;
  LOBYTE(v660) = -102;
  if ( v278 )
    v279 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v278);
  else
    v279 = 0;
  dword_D2DE9C = v279;
  LOBYTE(v660) = -103;
  v280 = LuaPlus::LuaObject::CreateTable(&v659, &v500, "CityBankTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DE9C, v280);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v500);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DE9C,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DE9C);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "GetNpcId", (int)sub_5BBF80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "GetCityLevel", (int)sub_5BCC00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "SetCurRentIndex", (int)sub_5BC0A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "AcquireList", (int)sub_5BBFD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "EnumItem", (int)sub_5BC0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "Close", (int)sub_5BC240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "Get_SetAccess", (int)sub_5BC480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "Get_GetAccess", (int)sub_5BC280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "Set_SetAccess", (int)sub_5BC680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "Set_GetAccess", (int)sub_5BC820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "SendAccess", (int)sub_5BC9D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "OpenRecord", (int)sub_5BCAF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "GetRecordNum", (int)sub_5BCBC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "GetCurPageRecordNum", (int)sub_5BCC40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DE9C, "EnumMessage", (int)sub_5BCC80, 0);
  v281 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v395, &unk_D2DEA0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v561, v281);
  LOBYTE(v660) = -101;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v561, (const struct LuaPlus::LuaObject *)dword_D2DE9C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "CityBank", (struct LuaPlus::LuaObject *)&v561);
  v282 = operator new(0x18u);
  v464 = v282;
  LOBYTE(v660) = -100;
  if ( v282 )
    v283 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v282);
  else
    v283 = 0;
  dword_D31ED8 = v283;
  LOBYTE(v660) = -101;
  v284 = LuaPlus::LuaObject::CreateTable(&v659, &v498, "TServerUI", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31ED8, v284);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v498);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31ED8,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31ED8);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetTSMemRecordScore", (int)sub_670DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetMemRecordZhanTuanName", (int)sub_670E50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetMemRecord2WorldID", (int)sub_670EB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetMemRecord2ZhantuanID", (int)sub_670F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetTotalDamage", (int)sub_6712D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetTotalKill", (int)sub_671500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetMyAttackZhanTuanID", (int)sub_671570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetMemRecordResult", (int)sub_670FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetZhanTuanNameByWorldID", (int)sub_671000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetAttackInfoByIdx", (int)sub_6710D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetMyTSSceneBYZhanTuanID", (int)sub_671280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31ED8, "GetMonsterNamebyDataID", (int)sub_671600, 0);
  v285 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v393, &unk_D31ED4);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v625, v285);
  LOBYTE(v660) = -99;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v625, (const struct LuaPlus::LuaObject *)dword_D31ED8);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "TServerUI", (struct LuaPlus::LuaObject *)&v625);
  v286 = operator new(0x18u);
  v464 = v286;
  LOBYTE(v660) = -98;
  if ( v286 )
    v287 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v286);
  else
    v287 = 0;
  dword_D32910 = v287;
  LOBYTE(v660) = -99;
  v288 = LuaPlus::LuaObject::CreateTable(&v659, &v496, "KAlliance", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32910, v288);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v496);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D32910,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D32910);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskAllianceInfo", (int)sub_678C80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "JoinAlliance", (int)sub_678D50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetActLeaderNum", (int)sub_67AA60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetActLeaderName", (int)sub_67AAD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetTopLeaderName", (int)sub_67AC40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetActingNum", (int)sub_678ED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetActingName", (int)sub_678F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskAlliLeaderInfo", (int)sub_679090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAlliUserNum", (int)sub_679160, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAlliUserInfo", (int)sub_6791C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskAllianceGuildDetail", (int)sub_679530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAlliGuildNum", (int)sub_679620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAlliGuildDetailInfo", (int)sub_67A0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "OpenMyAllianceFrame", (int)sub_67A310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskAllianceEliteList", (int)sub_6797E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAlliEliteNum", (int)sub_67A430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAlliEliteInfo", (int)sub_67A490, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AppointComActing", (int)sub_67A620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAlliFightScoreArmy", (int)sub_679670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliFightScoreArmy", (int)sub_679720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliFightScore", (int)sub_6797A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyContri", (int)sub_6799B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyUnit", (int)sub_6799F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAlliFightScoreLogi", (int)sub_6796E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliFightScoreLogi", (int)sub_679760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetKingFightScore", (int)sub_683920, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyKingFightScore", (int)sub_683960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetTopGuildName", (int)sub_67AD70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAlliUserInfoDetail", (int)sub_67AEA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "Appoint", (int)sub_67B0D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskMyGuildDetail", (int)sub_67B5B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliGuildNum", (int)sub_67B680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliGuildDetailInfo", (int)sub_67B760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskMyArmyInfo", (int)sub_67B8C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliUserInfo", (int)sub_67BF10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliUserNum", (int)sub_67B950, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliUserNum_RecordStone", (int)sub_67BB10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskMyLogiInfo", (int)sub_67C150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskMyLogiRecordStoneInfo", (int)sub_67C1E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "ApplyActingGuild", (int)sub_67C270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "QuitAlliance", (int)sub_67C310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskAllianceTongChou", (int)sub_6798C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "RemoveComActing", (int)sub_67A780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "Remove", (int)sub_67C3B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "MoveArmyMember", (int)sub_67A8E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "RemoveArmyMember", (int)sub_67C530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "PrepareMembersInfomation_RecordStone", (int)sub_680190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMySortAlliUserInfo_RecordStone", (int)sub_6805A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "PrepareMembersInfomation", (int)sub_67E830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMySortAlliUserInfo", (int)sub_67E8B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "PrepareAllianceEliteInfomation", (int)sub_680830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetSortAlliEliteNum", (int)sub_680DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetSortAlliEliteInfo", (int)sub_6808B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "SortAppointArmy", (int)sub_680F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyGetAllianceName", (int)sub_67C6F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMemberConfraternity", (int)sub_67C790, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMemberConfraternityEx", (int)sub_67CB70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "SortMemberConfraternity", (int)sub_67CC80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "SortMemberZoneID", (int)sub_67D190, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMemberZoneIDNum", (int)sub_67D310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMemberZoneIDIndex", (int)sub_67D360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetSortMemberConfraternityNum", (int)sub_67D420, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetZhangLaoNum", (int)sub_67D480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAskAllianceID", (int)sub_679960, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMySortAlliUserData", (int)sub_67EAC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "RemoveSortAlliUser", (int)sub_67F1B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "MoveSortArmyMember", (int)sub_67F330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "RemoveSortArmyMember", (int)sub_67F4D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AppointSortAlliUser", (int)sub_67F620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "ShowAlliUserPopMenu", (int)sub_67ED20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetJoinState", (int)sub_679A30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "SortAppointComActing", (int)sub_6811F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "SortRemoveComActing", (int)sub_681320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "SortRemove", (int)sub_681450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetSortAlliEliteData", (int)sub_680AF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "SortAppointArmyLeader", (int)sub_681060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AppointSortFindMe", (int)sub_67F7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "PrepareGuildInfomation", (int)sub_682200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetSortMyAlliGuildDetailInfo", (int)sub_682280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetSortAlliEliteLeaderNum", (int)sub_6815B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliUserOnlineNum", (int)sub_67BA30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliUserOnlineNum_RecordStone", (int)sub_67BBF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "SortMemberConfraternityForItemAssignment", (int)sub_67D900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetSortMemberConfraternityNumForItemAssignment", (int)sub_67DD60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMemberConfraternityForItemAssignment", (int)sub_67DDC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetLeagueInfoMember", (int)sub_67D4F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetLeagueInfoGuild", (int)sub_67D6F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliGuildActingNum", (int)sub_67B6D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliUserTotalNum", (int)sub_67BCD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliUsetTotalOnlineNum", (int)sub_67BD80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyAlliuserScore", (int)sub_67BE30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetOccupiedInfostr", (int)sub_67E040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetALCCurrentHumanCount", (int)sub_682830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetALCRedTeamHumanCount", (int)sub_682890, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetALCBlueTeamHumanCount", (int)sub_682930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetALCRedTeamRealHumanCount", (int)sub_6828E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetALCBlueTeamRealHumanCount", (int)sub_682980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetALCHumanBaseInfo", (int)sub_6829D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetALCRedTeamHumanBaseInfo", (int)sub_682B70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetALCBlueTeamHumanBaseInfo", (int)sub_682D10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetALCSelfBeloneTeam", (int)sub_682EB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "BeginSearch", (int)sub_682010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyGuildScore", (int)sub_679E20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "FlushSelfEquip", (int)sub_679E60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskAllianceHistoryBaseInfo", (int)sub_67A020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "IsAllianceLeader", (int)sub_6821B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "InviteRaid", (int)sub_679F40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetExamine", (int)sub_67C100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAwardHistoryTotalCount", (int)sub_67E510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetAwardHistoryDetail", (int)sub_67E580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AskAllianceAwardHistory", (int)sub_67E770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "ReflashLeaderApplyInfo", (int)sub_682F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetVaildApplyNum", (int)sub_682FA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMyRank", (int)sub_682FE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "ApplyAllianceLeader", (int)sub_683020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetSelectAllianceInfo", (int)sub_6830C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetCurSelectGuildName", (int)sub_683230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetApplyGuildInfo", (int)sub_683470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "SelectAlliance", (int)sub_683770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "RemoveActingGuild", (int)sub_6839A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "AppointActingGuild", (int)sub_683AB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32910, "GetMemberConfraternityAllMinxin", (int)sub_683BC0, 0);
  v289 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v391, &off_C6EDB4);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v589, v289);
  LOBYTE(v660) = -97;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v589, (const struct LuaPlus::LuaObject *)dword_D32910);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "KAlliance", (struct LuaPlus::LuaObject *)&v589);
  v290 = operator new(0x18u);
  v464 = v290;
  LOBYTE(v660) = -96;
  if ( v290 )
    v291 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v290);
  else
    v291 = 0;
  dword_D34658 = v291;
  LOBYTE(v660) = -97;
  v292 = LuaPlus::LuaObject::CreateTable(&v659, &v494, "MaterialStation", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D34658, v292);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v494);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D34658,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D34658);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "AskDetailInfo", (int)sub_6D0410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "TakeOutMaterial", (int)sub_6D0510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "CalcBuyCost", (int)sub_6D1500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "SubmitShopList", (int)sub_6D0BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "GetIsCreator", (int)sub_6D1B60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "DelMaterialStationMember", (int)sub_6D0A10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "QuitTheMemberList", (int)sub_6D0B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "EnumCommodityInfo", (int)sub_6D0D40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "EnmuToBuyCommodityInfo", (int)sub_6D0EB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "GetShopCartItemNum", (int)sub_6D1430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "ReleaseOPLock", (int)sub_6D1AD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "GetMaterialSationAllWorth", (int)sub_6D1470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "GetStationMemberCount", (int)sub_6D1580, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "EnumMemberInfo", (int)sub_6D15F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "GetMaterialStationNum", (int)sub_6D1BA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "EnumMaterialStationInfo", (int)sub_6D1BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "ClearUpShopCart", (int)sub_6D1AA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "GetMaterialsInStationNum", (int)sub_6D1CA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "EnumMaterialInStationInfo", (int)sub_6D1D60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "GetCreatorName", (int)sub_6D0BC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "EnumTradeRecord", (int)sub_6D1F20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "AddCommodityIntoShopCart", (int)sub_6D0FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "DelCommodityFromShopCart", (int)sub_6D1390, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "AddMaterialStationMemberByGUID", (int)sub_6D06D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "AddMaterialStationMemberByRaid", (int)sub_6D07F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "AddMaterialStationMemberByFriendInfo", (int)sub_6D08E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "CalcMaxNumCanGet", (int)sub_6D1E60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "SetCaredObjId", (int)sub_6D0CB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D34658, "GetCaredObjId", (int)sub_6D0D00, 0);
  v293 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v389, &unk_D34788);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v627, v293);
  LOBYTE(v660) = -95;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v627, (const struct LuaPlus::LuaObject *)dword_D34658);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "MaterialStation", (struct LuaPlus::LuaObject *)&v627);
  v294 = operator new(0x18u);
  v464 = v294;
  LOBYTE(v660) = -94;
  if ( v294 )
    v295 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v294);
  else
    v295 = 0;
  dword_D33F50 = v295;
  LOBYTE(v660) = -95;
  v296 = LuaPlus::LuaObject::CreateTable(&v659, &v492, "KBuildingGroup", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D33F50, v296);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v492);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D33F50,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D33F50);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "EnumKBuildingInfo", (int)sub_6CA610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "DoBuildingLevelUp", (int)sub_6CABC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "DoBuildBuilding", (int)sub_6CAD30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "DoBuildingRepair", (int)sub_6CAED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetKBuildingInfoByPos", (int)sub_6CA820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "FiredUp", (int)sub_6CB040, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "CheckFiredUp", (int)sub_6CB100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetIsOpAuthorized", (int)sub_6CB1C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetKBuildingGroupGlobalData", (int)sub_6CAAE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetLevelUpFundAndTimeCost", (int)sub_6CB200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetCreateFundAndTimeCost", (int)sub_6CB370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetMaintainFundCost", (int)sub_6CB480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetRepairFundCost", (int)sub_6CB570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "Pos2BuildingType", (int)sub_6CB6B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetKBuildingOccupiedInfo", (int)sub_6CB770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "SysKBuildingGroupOccupiedInfo", (int)sub_6CB7B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetKBuildingGroupBaseData", (int)sub_6CB870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetBuildNeedMainBuildingLevel", (int)sub_6CB930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "GetMainBuildingLevel", (int)sub_6CBA80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F50, "CheckIfCanLevelUp", (int)sub_6CBAE0, 0);
  v297 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v387, &dword_D33F68);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v571, v297);
  LOBYTE(v660) = -93;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v571, (const struct LuaPlus::LuaObject *)dword_D33F50);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "KBuildingGroup", (struct LuaPlus::LuaObject *)&v571);
  v298 = operator new(0x18u);
  v464 = v298;
  LOBYTE(v660) = -92;
  if ( v298 )
    v299 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v298);
  else
    v299 = 0;
  dword_D33F54 = v299;
  LOBYTE(v660) = -93;
  v300 = LuaPlus::LuaObject::CreateTable(&v659, &v490, "KAllianceShop", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D33F54, v300);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v490);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D33F54,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D33F54);
  sub_877220((LuaPlus::LuaObject *)dword_D33F54, "EnumKAllianceShopCommodityInfo", (int)sub_6CC570, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F54, "BuyItem", (int)sub_6CC6D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F54, "CalcMaxNumCanBuy", (int)sub_6CC9E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F54, "CheckIsMultiBuy", (int)sub_6CC8D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F54, "GetAllianceContributionRate", (int)sub_6CC880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F54, "OpenBuyConfirmMessageBox", (int)sub_6CCD80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F54, "GetCommodityTypesNum", (int)sub_6CCE00, 0);
  v301 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v385, &unk_C72E88);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v629, v301);
  LOBYTE(v660) = -91;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v629, (const struct LuaPlus::LuaObject *)dword_D33F54);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "KAllianceShop", (struct LuaPlus::LuaObject *)&v629);
  v302 = operator new(0x18u);
  v464 = v302;
  LOBYTE(v660) = -90;
  if ( v302 )
    v303 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v302);
  else
    v303 = 0;
  dword_D33F58 = v303;
  LOBYTE(v660) = -91;
  v304 = LuaPlus::LuaObject::CreateTable(&v659, &v488, "KMSDShop", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D33F58, v304);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v488);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D33F58,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D33F58);
  sub_877220((LuaPlus::LuaObject *)dword_D33F58, "EnumKMSDShopCommodityInfo", (int)sub_6CD120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F58, "CheckIsMultiBuy", (int)sub_6CD270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F58, "OpenBuyConfirmMessageBox", (int)sub_6CD370, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D33F58, "GetCommodityTypesNum", (int)sub_6CD3F0, 0);
  v305 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v383, &unk_C72EA8);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v591, v305);
  LOBYTE(v660) = -89;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v591, (const struct LuaPlus::LuaObject *)dword_D33F58);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "KMSDShop", (struct LuaPlus::LuaObject *)&v591);
  v306 = operator new(0x18u);
  v464 = v306;
  LOBYTE(v660) = -88;
  if ( v306 )
    v307 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v306);
  else
    v307 = 0;
  dword_D31924 = v307;
  LOBYTE(v660) = -89;
  v308 = LuaPlus::LuaObject::CreateTable(&v659, &v486, "KMCorps", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31924, v308);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v486);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31924,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31924);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "GetKMCorpsNameMyself", (int)sub_61AC80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "GetKMCorpsMemInfoMyself", (int)sub_61ACB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "GetKMCorpsNameById", (int)sub_61AE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "GetKMCorpsMemInfoById", (int)sub_61AEA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "IsKMCorpsLeader", (int)sub_61B050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "AdjustMemberPosition", (int)sub_61B140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "SendInviteRaidMsg", (int)sub_61B290, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "OpenMenu", (int)sub_61B320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "GetKMCopyScenePlayerInfoByIdx", (int)sub_61B670, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "GetKMTwoCorpsNameInCopyScene", (int)sub_61B870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "GetKMCorpsPK_Result_Info", (int)sub_61B8C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "GetKMCorpsPK_LeftTimes", (int)sub_61B930, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "GetKMCopySceneFirstKillerType", (int)sub_61B970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "SetKMMainTargetByUIIdx", (int)sub_61B9B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31924, "IsKMCorpsGameOver", (int)sub_61BAB0, 0);
  v309 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v381, &unk_D31920);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v631, v309);
  LOBYTE(v660) = -87;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v631, (const struct LuaPlus::LuaObject *)dword_D31924);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "KMCorps", (struct LuaPlus::LuaObject *)&v631);
  v310 = operator new(0x18u);
  v464 = v310;
  LOBYTE(v660) = -86;
  if ( v310 )
    v311 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v310);
  else
    v311 = 0;
  dword_D32BC8 = v311;
  LOBYTE(v660) = -87;
  v312 = LuaPlus::LuaObject::CreateTable(&v659, &v484, "BieYePetCreateColor", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32BC8, v312);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v484);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetBieYePetName", (int)sub_686C10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "SetBieYeCreatePetType", (int)sub_686D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "BieYeCutePetProcreate_Clear", (int)sub_686D80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "LockBieYeCutePetProcreate", (int)sub_686DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "ConfirmBieYeCutePetProcreate", (int)sub_686DB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "SetCanFanzhiPet", (int)sub_686EB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetMengChongNameByMCID", (int)sub_687300, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetMengChongCanColorInfo", (int)sub_686F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "ConfirmBieYeCutePetProcreate", (int)sub_686DB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetMengChongTypeNum", (int)sub_6871B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetMengChongInfoByIndex", (int)sub_687200, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetColorInfoMengChongByIndex", (int)sub_687820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetCanCreateMengChongCountByMCID", (int)sub_687720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetCreateInfoMengChongByIndex", (int)sub_6879E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetCanColorMengChongCountByMCID", (int)sub_687400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "IsCouldFindItSelf", (int)sub_687500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetNoColorByMengChongID", (int)sub_687610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetColorInfoMengChongByIndex", (int)sub_687820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32BC8, "GetColorName", (int)sub_687B50, 0);
  v313 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v379, &unk_D32BD0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v557, v313);
  LOBYTE(v660) = -85;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v557, (const struct LuaPlus::LuaObject *)dword_D32BC8);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "BieYePetCreateColor", (struct LuaPlus::LuaObject *)&v557);
  v314 = operator new(0x18u);
  v464 = v314;
  LOBYTE(v660) = -84;
  if ( v314 )
    v315 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v314);
  else
    v315 = 0;
  dword_D32D98 = v315;
  LOBYTE(v660) = -85;
  v316 = LuaPlus::LuaObject::CreateTable(&v659, &v482, "DecoWeaponUI", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D32D98, v316);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v482);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D32D98,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D32D98);
  sub_877220((LuaPlus::LuaObject *)dword_D32D98, "DecoWeaponAvatarChangeWeapon", (int)sub_68F2C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32D98, "GetDecoWeaponConverInfo", (int)sub_68F3B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32D98, "GetDecoWeaponLevelInfo", (int)sub_68F4F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32D98, "GetDecoWeaponLevelData", (int)sub_68F680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32D98, "GetDecoWeaponNum", (int)sub_68F8D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32D98, "EnumDecoWeapon", (int)sub_68F910, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32D98, "GetEquipBaseDecoWeaponData", (int)sub_68FA10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32D98, "DecoWeaponAvatarPlayAction", (int)sub_68F320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D32D98, "GetDecoWeapActionNum", (int)sub_68FC70, 0);
  v317 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v377, &unk_D32DA0);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v633, v317);
  LOBYTE(v660) = -83;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v633, (const struct LuaPlus::LuaObject *)dword_D32D98);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "DecoWeaponUI", (struct LuaPlus::LuaObject *)&v633);
  v318 = operator new(0x18u);
  v464 = v318;
  LOBYTE(v660) = -82;
  if ( v318 )
    v319 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v318);
  else
    v319 = 0;
  dword_D2DD18 = v319;
  LOBYTE(v660) = -83;
  v320 = LuaPlus::LuaObject::CreateTable(&v659, &v480, "BieYeUI", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DD18, v320);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v480);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DD18,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DD18);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBuildingsLevel", (int)sub_5A36D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBuildingsLevelTime", (int)sub_5A37B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "AskBieYeBaseInfo", (int)sub_5A3E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieYeBaseInfo", (int)sub_5A3F00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureCountByItemIDZH", (int)sub_5A65B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureCostZH", (int)sub_5A66C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBuildingsLevelupData", (int)sub_5A3A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "BuildingLevelUpWithIndex", (int)sub_5A3BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "BuildingLevelUpWithBuildType", (int)sub_5A3D00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "MoveFurnitureForItemId", (int)sub_5A47B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "MoveFurnitureForObjId", (int)sub_5A4C80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "ViewFurniture", (int)sub_5A5450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "ReleaseFurniture", (int)sub_5A5510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieYeAreaType", (int)sub_5A4700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureIDByType", (int)sub_5A5BC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureIDByTypePosAndQuality", (int)sub_5A5D70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureNeedByTypePosAndQuality", (int)sub_5A5FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureNeedHeChengFurnitureIDByFurnitureID", (int)sub_5A6230, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetMaterialOutputName", (int)sub_5A5680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetMaterialOutputData", (int)sub_5A59D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "BieYePlantingSetModel", (int)sub_5A5B50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetMaterialOutputNameById", (int)sub_5A58A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureTypeByItemID", (int)sub_5A6450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "AskBieYeJiaYanUserInfo", (int)sub_5A67E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieYeJiaYanUserCount", (int)sub_5A6880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieYeJiaYanRound", (int)sub_5A68C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieYeJiaYanUserInfo", (int)sub_5A6900, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureObjNum", (int)sub_5A6A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "BeginRotationFurniture", (int)sub_5A4DE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "OkRotationFurniture", (int)sub_5A4F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "RotationFurniture", (int)sub_5A5130, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "CancelRotationFurniture", (int)sub_5A51F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureNameForObjId", (int)sub_5A5320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBuildingsLevelNeedTime", (int)sub_5A3890, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "AcquireFurnitureInfo", (int)sub_5A67D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "IsBieYeScene", (int)sub_5A6AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "IsBieYeTemplate", (int)sub_5A6B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "PrepareFurnitureShopItem", (int)sub_5A6B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureShopItemNum", (int)sub_5A6CA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "EnumFurnitureShopItem", (int)sub_5A6CF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurnitureShopItemInfo", (int)sub_5A6E40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "ObjReserveAll", (int)sub_5A7030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "ObjDestroyIt", (int)sub_5A72D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetServerIdByObjId", (int)sub_5A7400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "ObjReserveAll_NoObj", (int)sub_5A71A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurObjName", (int)sub_5A72E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieyeComfortToplistData", (int)sub_5A7520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "VoteComfortTopList", (int)sub_5A7830, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "EnterComfortTopList", (int)sub_5A7990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "SetCplVoteGift", (int)sub_5A7AA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "FurnitureAttachPlayer", (int)sub_5A7C00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurPlayerAnimNum", (int)sub_5A7F20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurPlayerAnimName", (int)sub_5A8100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurPlayerIsCanAnim", (int)sub_5A82F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetFurtureLimit", (int)sub_5A8440, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "SetFurtureLimit", (int)sub_5A84E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieYeStyleInfo", (int)sub_5A86F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieYeStyle_DisplayItem", (int)sub_5A88B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieYeStyleItemTime", (int)sub_5A8980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieYeStyleTime", (int)sub_5A8B00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetBieYeStyleData", (int)sub_5A8BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD18, "GetMengChongTypeByItemID", (int)sub_5A8590, 0);
  v321 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v375, &unk_D2DD1C);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v593, v321);
  LOBYTE(v660) = -81;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v593, (const struct LuaPlus::LuaObject *)dword_D2DD18);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "BieYeUI", (struct LuaPlus::LuaObject *)&v593);
  v322 = operator new(0x18u);
  v464 = v322;
  LOBYTE(v660) = -80;
  if ( v322 )
    v323 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v322);
  else
    v323 = 0;
  dword_D36F38 = v323;
  LOBYTE(v660) = -81;
  v324 = LuaPlus::LuaObject::CreateTable(&v659, &v478, "WuLinZhiDian", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D36F38, v324);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v478);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D36F38,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D36F38);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "IsWuLinZhiDianScene", (int)sub_742FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "IsTeamLeader", (int)sub_743030, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "IsDoubleAwardTime", (int)sub_7430E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetMaxStage", (int)sub_743120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "SetChooseStage", (int)sub_743160, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetChooseStage", (int)sub_7431E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "SetAverageStage", (int)sub_743220, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetAverageStage", (int)sub_7432A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "SetTeamMemberCount", (int)sub_7432E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetTeamMemberCount", (int)sub_743360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetTeamMemberInfo", (int)sub_743420, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "SetTeamMemberState", (int)sub_743610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetTeamMemberState", (int)sub_7436F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetAvalibleAwardCount", (int)sub_7437C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetStageState", (int)sub_743800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetWeekAwardInfo", (int)sub_743890, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetCurWeekCount", (int)sub_7439D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D36F38, "GetCurBossIndex", (int)sub_743A10, 0);
  v325 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v373, &unk_D36F3C);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v635, v325);
  LOBYTE(v660) = -79;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v635, (const struct LuaPlus::LuaObject *)dword_D36F38);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "WuLinZhiDian", (struct LuaPlus::LuaObject *)&v635);
  v326 = operator new(0x18u);
  v464 = v326;
  LOBYTE(v660) = -78;
  if ( v326 )
    v327 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v326);
  else
    v327 = 0;
  dword_D2DD90 = v327;
  LOBYTE(v660) = -79;
  v328 = LuaPlus::LuaObject::CreateTable(&v659, &v476, "BieYeFurniture", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DD90, v328);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v476);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DD90,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DD90);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "AcquireList", (int)sub_5A9C00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "AcquireListWithCangKuHC", (int)sub_5A9D40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetCurRentIndex", (int)sub_5A9DD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetPageIndex", (int)sub_5A9E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetChooseIndex", (int)sub_5A9F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetCurRentIndex", (int)sub_5A9E30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetPageIndex", (int)sub_5A9ED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetChooseIndex", (int)sub_5A9F70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetCurInner", (int)sub_5A9FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetCurInner", (int)sub_5A9FF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetBieYeFurnitureInCangKuOrPut", (int)sub_5AA090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetBieYeFurnitureInCangKuOrPut", (int)sub_5AA050, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "EnumItem", (int)sub_5AA0F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetNum", (int)sub_5AA2C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetContainerIndexByItemTableIndex", (int)sub_5AB1D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "Close", (int)sub_5AA240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "IsBieYeScene", (int)sub_5AA280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "BuyBieYeFurniture", (int)sub_5AA3E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetBieYeFurnitureCount", (int)sub_5AA350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetBieYeFurnitureComfort", (int)sub_5AA4E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetBieYeFurnitureCurCount", (int)sub_5AA610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetBieYeFurnitureType", (int)sub_5AA660, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetFurnitureModel", (int)sub_5AA700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetFurnitureCreateModel", (int)sub_5AA760, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetFurnitureDecorationModel", (int)sub_5AA7C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetBieYeFurnitureInfo", (int)sub_5AA820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "RemoveFuniture", (int)sub_5AAB40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetBieYeFurnitureTypeCount", (int)sub_5AA6B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetBieYeFurnitureLimitByBieYeLevel", (int)sub_5AAC30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetBieYePutFurnitureLimitByBieYeLevel", (int)sub_5AAD80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetBankFurTypeNum", (int)sub_5ABDF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurIDInBankByIndex", (int)sub_5ABE40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurTransferInfoById", (int)sub_5ABF40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetFurnitureTransferBeforeModel", (int)sub_5AAA20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetFurnitureTransferAfterModel", (int)sub_5AAA80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurCanTransferInfo", (int)sub_5AC120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurnitureNews", (int)sub_5AC3D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "SetFurnitureNewsModel", (int)sub_5AAAE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurCntInCangku", (int)sub_5AAC80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurCntInCangkuHC", (int)sub_5AAD00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurCreateInfo", (int)sub_5AAED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurTypeCntQulityInTbl", (int)sub_5AB250, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurQulityInTbl", (int)sub_5AB460, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurNamenTbl", (int)sub_5AB6D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurNameByFurnitureID", (int)sub_5ABC00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "GetFurNameByLevelAndTypeTbl", (int)sub_5AB970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DD90, "Lua_GetBieYeFurnitureBoxHaveFur", (int)sub_5ABD30, 0);
  v329 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v371, &unk_D2DD94);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v573, v329);
  LOBYTE(v660) = -77;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v573, (const struct LuaPlus::LuaObject *)dword_D2DD90);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "BieYeFurniture", (struct LuaPlus::LuaObject *)&v573);
  v330 = operator new(0x18u);
  v464 = v330;
  LOBYTE(v660) = -76;
  if ( v330 )
    v331 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v330);
  else
    v331 = 0;
  dword_D2DDC0 = v331;
  LOBYTE(v660) = -77;
  v332 = LuaPlus::LuaObject::CreateTable(&v659, &v474, "BieYeMengChong", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DDC0, v332);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v474);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DDC0,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DDC0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetNum", (int)sub_5ACD30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "SetCurRentIndex", (int)sub_5AC840, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYeMengChongLimitByBieYeLevel", (int)sub_5AD620, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYePutMengChongLimitByBieYeLevel", (int)sub_5AD6F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "BuyBieYeMengChong", (int)sub_5ACE00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_RemoveMengChong", (int)sub_5AF2F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_GetOutChong", (int)sub_5AF880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYeMengChongTypeCount", (int)sub_5AD0C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYeMengChongTypeSize", (int)sub_5AD170, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYeMengChongInfo", (int)sub_5AD2A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYeMengChongCurCount", (int)sub_5AD020, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "AcquireList", (int)sub_5AC740, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "EnumItem", (int)sub_5ACB60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetNum", (int)sub_5ACD30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "HandleMengChongMenuItem", (int)sub_5AEE70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYeMengChongFirstIndexByType", (int)sub_5AD1F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYeMengChongLastIndexByType", (int)sub_5AF240, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYeXiaoWoInfo", (int)sub_5AFBF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetXiaoWoLimit", (int)sub_5AFF70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetXiaoWoJieSuoLevelByIndex", (int)sub_5B0090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_AddXiaoWo", (int)sub_5B0160, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "BieYeMengChong_isHaveItem", (int)sub_5AE8C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_GetModelIDByMengChongIndex", (int)sub_5B0C00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Change_Name", (int)sub_5B0DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_isWeek", (int)sub_5B1140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_WeiYang", (int)sub_5B0430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_isBaoShi", (int)sub_5B11E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_MinuXiaoWo", (int)sub_5B0700, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "SetModelMengChong", (int)sub_5B1310, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_HaveXiaoWoChong", (int)sub_5B1280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongName", (int)sub_5B1350, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongExp", (int)sub_5B1410, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongBaoShiDu", (int)sub_5B14E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongXiaoWoIndex", (int)sub_5B15B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_GetMengChongIndexFromAction", (int)sub_5B1680, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_isOutter", (int)sub_5B0D20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "IsMaster", (int)sub_5B18D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_CanGetOut", (int)sub_5B1A00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongIsChengNian", (int)sub_5B1CE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongActionName1", (int)sub_5B1DF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongActionName2", (int)sub_5B1F80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongActionName3", (int)sub_5B2110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongActionName4", (int)sub_5B22A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongActionName5", (int)sub_5B2430, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongObjID", (int)sub_5B25C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "Lua_BieYeMengChong_GetFirstPos2IndexPos", (int)sub_5B2640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYeXiaoWoCount", (int)sub_5B26D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetBieYeXiaoWoChengNianState", (int)sub_5B2770, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongIsHave", (int)sub_5B2800, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "MengChongBackBag", (int)sub_5B28B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DDC0, "GetMengChongModleID", (int)sub_5B2D20, 0);
  v333 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v369, &unk_D2DDC4);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v637, v333);
  LOBYTE(v660) = -75;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v637, (const struct LuaPlus::LuaObject *)dword_D2DDC0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "BieYeMengChong", (struct LuaPlus::LuaObject *)&v637);
  v334 = operator new(0x18u);
  v464 = v334;
  LOBYTE(v660) = -74;
  if ( v334 )
    v335 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v334);
  else
    v335 = 0;
  dword_D2DEE0 = v335;
  LOBYTE(v660) = -75;
  v336 = LuaPlus::LuaObject::CreateTable(&v659, &v472, "CorpsUI_2016", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DEE0, v336);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v472);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DEE0,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DEE0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "CreateCorps", (int)sub_5C10D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetCorpsMemberInfoByIdx", (int)sub_5C12E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetDetailCorpsInfo", (int)sub_5C1520, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetCorpsMemberPost", (int)sub_5C1480, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "CorpsOper_InviteCorps", (int)sub_5C1810, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "CorpsOper_InviteCorps_Confirm", (int)sub_5C19F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "CorpsOper_AssignAssist", (int)sub_5C1C60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "CorpsOper_CancelAssist", (int)sub_5C1EA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "Corps_HasAssist", (int)sub_5C2100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "Corps_DismissCorps", (int)sub_5C2150, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "IsCorpsLeader", (int)sub_5C2610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "IsCorpsLeaderGuid", (int)sub_5C26B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "IsCorpsAssist", (int)sub_5C27C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "IsCorpsAssistGuid", (int)sub_5C2860, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetCorpsMemberCount", (int)sub_5C2970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "AskCorpsMemberJoinRaid", (int)sub_5C29C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "ChangeMemBatterSequ", (int)sub_5C2AA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "OpenMenu", (int)sub_5C2DC0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "Corps_KickCorpsMember", (int)sub_5C22A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "Corps_LeaveCorps", (int)sub_5C24C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetCopyScenePlayerInfoByIdx", (int)sub_5C3110, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetTwoCorpsNameInCopyScene", (int)sub_5C3320, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetCorpsPK_Result_Info", (int)sub_5C3380, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetCorpsPK_LeftTimes", (int)sub_5C3400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetCopySceneFirstKillerType", (int)sub_5C3450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetPriRChartsNodeInfo", (int)sub_5C34A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetRegRChartsNodeInfo", (int)sub_5C35A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "CanQueryRankingAgain", (int)sub_5C3720, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "RequsetRankingCharts", (int)sub_5C3780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetRankingTotalPage", (int)sub_5C3880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetRankingCurPage", (int)sub_5C38D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "RequsetCorpsInfo", (int)sub_5C3970, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetRankingStage", (int)sub_5C3920, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "IsCorpsGameOver", (int)sub_5C3A60, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "SetMainTargetByUIIdx", (int)sub_5C3AB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetFightPairCount", (int)sub_5C3CE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetFightPairInfoByIdx", (int)sub_5C3BB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetCorpLeaderIndex", (int)sub_5C3D30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetCorpAssistIndex", (int)sub_5C3DA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetFinalCorpsInfoByIdx", (int)sub_5C3E10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "SetPlayerWatchPosDirection", (int)sub_5C3EF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "CancelPlayerWatchPosDirection", (int)sub_5C44E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "SetSpecialSceneFlag", (int)sub_5C4530, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEE0, "GetZbsStage", (int)sub_5C45A0, 0);
  v337 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v367, &unk_D2DEDC);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v595, v337);
  LOBYTE(v660) = -73;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v595, (const struct LuaPlus::LuaObject *)dword_D2DEE0);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "CorpsUI_2016", (struct LuaPlus::LuaObject *)&v595);
  v338 = operator new(0x18u);
  v464 = v338;
  LOBYTE(v660) = -72;
  if ( v338 )
    v339 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v338);
  else
    v339 = 0;
  dword_D2DEEC = v339;
  LOBYTE(v660) = -73;
  v340 = LuaPlus::LuaObject::CreateTable(&v659, &v470, "CorpsUI_2018", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2DEEC, v340);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v470);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2DEEC,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2DEEC);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "SelectMpInfo", (int)sub_5C4750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "CreateCorps", (int)sub_5C4880, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetCorpsMemberInfoByIdx", (int)sub_5C4C00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetDetailCorpsInfo", (int)sub_5C4E80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetCorpsMemberPost", (int)sub_5C4DE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "CorpsOper_InviteCorps", (int)sub_5C5120, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "CorpsOper_InviteAnswer", (int)sub_5C5500, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "CorpsOper_AssignAssist", (int)sub_5C5690, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "CorpsOper_CancelAssist", (int)sub_5C58E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "Corps_HasAssist", (int)sub_5C5B50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "Corps_DismissCorps", (int)sub_5C5BA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "IsCorpsLeader", (int)sub_5C62A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "IsCorpsLeaderGuid", (int)sub_5C6340, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "IsCorpsAssist", (int)sub_5C6450, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "IsCorpsAssistGuid", (int)sub_5C64F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetCorpsMemberCount", (int)sub_5C6600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "AskCorpsMemberJoinRaid", (int)sub_5C6650, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "ChangeMemBatterSequ", (int)sub_5C6750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "OpenMenu", (int)sub_5C6A40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "Corps_KickCorpsMember", (int)sub_5C5D00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "Corps_LeaveCorps", (int)sub_5C5F30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "Corps_ChangeMenpai", (int)sub_5C6090, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetCopyScenePlayerInfoByIdx", (int)sub_5C6D90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetTwoCorpsNameInCopyScene", (int)sub_5C6FB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetCorpsPK_Result_Info", (int)sub_5C7010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetCorpsPK_LeftTimes", (int)sub_5C7060, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetCopySceneFirstKillerType", (int)sub_5C70B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetRankNode1Info", (int)sub_5C7100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetRankNodeVoteInfo", (int)sub_5C71F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetRankNode2Info", (int)sub_5C7400, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetRankNodeCount", (int)sub_5C75E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "CanQueryRankingAgain", (int)sub_5C7630, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "RequsetRankingCharts", (int)sub_5C7690, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "RequsetCorpsInfo", (int)sub_5C7780, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetRankingStage", (int)sub_5C7730, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "IsCorpsGameOver", (int)sub_5C7870, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "SetMainTargetByUIIdx", (int)sub_5C78C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetCorpLeaderIndex", (int)sub_5C79C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetCorpAssistIndex", (int)sub_5C7A30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetFinalCorpsInfoByIdx", (int)sub_5C7AA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "SetSpecialSceneFlag", (int)sub_5C7B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetZbsStage", (int)sub_5C7BF0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "VoteSetPrize", (int)sub_5C7D10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "VoteToCorps", (int)sub_5C7C40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "SendPlayerInfoToServer", (int)sub_5C7E90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetFightPairCount", (int)sub_5C80E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2DEEC, "GetFightPairInfoByIdx", (int)sub_5C8130, 0);
  v341 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v365, &unk_D2DEE8);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v639, v341);
  LOBYTE(v660) = -71;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v639, (const struct LuaPlus::LuaObject *)dword_D2DEEC);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "CorpsUI_2018", (struct LuaPlus::LuaObject *)&v639);
  v342 = operator new(0x18u);
  v464 = v342;
  LOBYTE(v660) = -70;
  if ( v342 )
    v343 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v342);
  else
    v343 = 0;
  dword_D31A1C = v343;
  LOBYTE(v660) = -71;
  v344 = LuaPlus::LuaObject::CreateTable(&v659, &v468, "MaritialSys", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31A1C, v344);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v468);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31A1C,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31A1C);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMaritialTodayNum", (int)sub_62C080, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMaritiaLTodayMultiNum", (int)sub_62C0C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMaritiaFreezeState", (int)sub_62C100, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMaritiaRemainPoint", (int)sub_62C140, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMaritiaAlreadyPoint", (int)sub_62C180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMaritiaAttrs", (int)sub_62C2D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMaritiaAttrByIndex", (int)sub_62C600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMaritiaAttrInfo", (int)sub_62C690, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "HasFinishWuYiMisson", (int)sub_62C7A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMartialLevelInfo", (int)sub_62C8F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMaritiaExp", (int)sub_62C470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMaritiaLevel", (int)sub_62C4B0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMartialAdvanceByIndex", (int)sub_62CA70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMartialAdvanceMaxLevel", (int)sub_62CC20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMartialAdvanceCostMoney", (int)sub_62CCB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMartialAdvanceCostItem", (int)sub_62CE20, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMartialAdvancePersent", (int)sub_62D010, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetMartialAttrNameByIndex", (int)sub_62D180, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetLastDayMonster", (int)sub_62D270, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetLastDayMonsterTip", (int)sub_62D2E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "SetLastDayMonsterTip", (int)sub_62D330, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetOtherMartialEnchance", (int)sub_62D3A0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetTalentRemainPoint", (int)sub_62D600, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetTalentLevelBylayerID", (int)sub_62D640, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetTalentInfo", (int)sub_62D7F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetTalentDescInfo", (int)sub_62D8E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31A1C, "GetTalentNeedMartialLevel", (int)sub_62D9D0, 0);
  v345 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v363, &unk_D31A20);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v563, v345);
  LOBYTE(v660) = -69;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v563, (const struct LuaPlus::LuaObject *)dword_D31A1C);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "MaritialSys", (struct LuaPlus::LuaObject *)&v563);
  v346 = operator new(0x18u);
  v464 = v346;
  LOBYTE(v660) = -68;
  if ( v346 )
    v347 = LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v346);
  else
    v347 = 0;
  dword_D35A80 = v347;
  LOBYTE(v660) = -69;
  v348 = LuaPlus::LuaObject::CreateTable(&v659, &v466, "ClientMovieTable", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D35A80, v348);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v466);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D35A80,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D35A80);
  v349 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v460, &unk_D35A84);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v641, v349);
  LOBYTE(v660) = -67;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v641, (const struct LuaPlus::LuaObject *)dword_D35A80);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "ClientMovie", (struct LuaPlus::LuaObject *)&v641);
  sub_877220((LuaPlus::LuaObject *)dword_D35A80, "TestPlay", (int)sub_6D3E70, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A80, "Play", (int)sub_6D3E90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A80, "Pause", (int)sub_6D3F10, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A80, "Stop", (int)sub_6D3F50, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A80, "HasMovie", (int)sub_6D3FD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A80, "IsPlaying", (int)sub_6D3F90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D35A80, "ParseTalkParam", (int)sub_6D4050, 0);
  v350 = operator new(0x18u);
  v464 = v350;
  LOBYTE(v660) = -66;
  if ( v350 )
    v351 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v350);
  else
    v351 = 0;
  dword_D31E60 = v351;
  LOBYTE(v660) = -67;
  v352 = LuaPlus::LuaObject::CreateTable(&v659, &v505, "SJTX", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D31E60, v352);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v505);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D31E60,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D31E60);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXTeamName", (int)sub_666360, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXTeamZoneWorldID", (int)sub_6663D0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXSceneState", (int)sub_666470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXSceneRemainTime", (int)sub_6664C0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXScenePlayerData", (int)sub_666510, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXSceneSelfSuoShu", (int)sub_666790, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXSceneFirstKillerResult", (int)sub_6668F0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXSceneMatchResult", (int)sub_666940, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXSceneJiFen", (int)sub_666990, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXSceneMatchType", (int)sub_666A90, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXSceneRound", (int)sub_666AE0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnGetSJTXSceneSceneState", (int)sub_666B30, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaFnSetSJTXMainTargetByUIIdx", (int)sub_666B80, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaGetPortraitInfo", (int)sub_666CB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D31E60, "LuaSetSpecialSceneFlag", (int)sub_666D80, 0);
  v353 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v366, &unk_D31E64);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v597, v353);
  LOBYTE(v660) = -65;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v597, (const struct LuaPlus::LuaObject *)dword_D31E60);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "SJTX", (struct LuaPlus::LuaObject *)&v597);
  v354 = operator new(0x18u);
  v464 = v354;
  LOBYTE(v660) = -64;
  if ( v354 )
    v355 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v354);
  else
    v355 = 0;
  dword_D2E208 = v355;
  LOBYTE(v660) = -65;
  v356 = LuaPlus::LuaObject::CreateTable(&v659, &v471, "FashionDepot", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2E208, v356);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v471);
  LuaPlus::LuaObject::SetObject(
    (LuaPlus::LuaObject *)dword_D2E208,
    "__index",
    (struct LuaPlus::LuaObject *)dword_D2E208);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnJudgeBagItem", (int)sub_609B00, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnGetFashionDepotItem", (int)sub_609CD0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnSendAskFashionDepotData", (int)sub_609ED0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnRefreshFashionDepot", (int)sub_60A000, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnSendFashionDepotOperation", (int)sub_60A2E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnGetWearCacheFashionData", (int)sub_60A470, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnGetWearEndCacheData", (int)sub_60A5E0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnGetFashionName", (int)sub_60A750, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnGetFashionDataVisualDesc", (int)sub_60A820, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnReWearFromFashionDepot", (int)sub_60ADB0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnRestoreFashionDepot", (int)sub_60B280, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnSlotChangeRestoreFashionDepot", (int)sub_60B610, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnGetFashionSpecialVisualName", (int)sub_60B980, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnInitCommonGiftDuiHuanShop", (int)sub_60BA40, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnGetCommonGiftDuiHuanShopGoodsNum", (int)sub_60BAA0, 0);
  sub_877220((LuaPlus::LuaObject *)dword_D2E208, "LuaFnGetCommonGiftDuiHuanShopGoodsInfo", (int)sub_60BB00, 0);
  v357 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v458, &unk_D2E20C);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v643, v357);
  LOBYTE(v660) = -63;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v643, (const struct LuaPlus::LuaObject *)dword_D2E208);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "FashionDepot", (struct LuaPlus::LuaObject *)&v643);
  v358 = operator new(0x18u);
  v464 = v358;
  LOBYTE(v660) = -62;
  if ( v358 )
    v359 = (void *)LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)v358);
  else
    v359 = 0;
  dword_D2E260 = v359;
  LOBYTE(v660) = -63;
  v360 = LuaPlus::LuaObject::CreateTable(&v659, &v548, "GuiShiUI", 0, 0);
  LuaPlus::LuaObject::operator=(dword_D2E260, v360);
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v548);
  sub_614D10();
  v361 = (const struct LuaPlus::LuaStackObject *)LuaPlus::LuaState::BoxPointer(v3, &v410, &dword_D2E264);
  LuaPlus::LuaObject::LuaObject((LuaPlus::LuaObject *)&v575, v361);
  LOBYTE(v660) = -61;
  LuaPlus::LuaObject::SetMetaTable((LuaPlus::LuaObject *)&v575, (const struct LuaPlus::LuaObject *)dword_D2E260);
  LuaPlus::LuaObject::SetObject((LuaPlus::LuaObject *)&v659, "GuiShiUI", (struct LuaPlus::LuaObject *)&v575);
  LOBYTE(v660) = -63;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v575);
  LOBYTE(v660) = -65;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v643);
  LOBYTE(v660) = -67;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v597);
  LOBYTE(v660) = -69;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v641);
  LOBYTE(v660) = -71;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v563);
  LOBYTE(v660) = -73;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v639);
  LOBYTE(v660) = -75;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v595);
  LOBYTE(v660) = -77;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v637);
  LOBYTE(v660) = -79;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v573);
  LOBYTE(v660) = -81;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v635);
  LOBYTE(v660) = -83;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v593);
  LOBYTE(v660) = -85;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v633);
  LOBYTE(v660) = -87;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v557);
  LOBYTE(v660) = -89;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v631);
  LOBYTE(v660) = -91;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v591);
  LOBYTE(v660) = -93;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v629);
  LOBYTE(v660) = -95;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v571);
  LOBYTE(v660) = -97;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v627);
  LOBYTE(v660) = -99;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v589);
  LOBYTE(v660) = -101;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v625);
  LOBYTE(v660) = -103;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v561);
  LOBYTE(v660) = -105;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v623);
  LOBYTE(v660) = -107;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v587);
  LOBYTE(v660) = -109;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v621);
  LOBYTE(v660) = -111;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v569);
  LOBYTE(v660) = -113;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v619);
  LOBYTE(v660) = -115;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v585);
  LOBYTE(v660) = -117;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v617);
  LOBYTE(v660) = -119;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v553);
  LOBYTE(v660) = -121;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v615);
  LOBYTE(v660) = -123;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v583);
  LOBYTE(v660) = -125;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v613);
  LOBYTE(v660) = -127;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v567);
  LOBYTE(v660) = 127;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v611);
  LOBYTE(v660) = 125;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v581);
  LOBYTE(v660) = 123;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v609);
  LOBYTE(v660) = 121;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v559);
  LOBYTE(v660) = 119;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v651);
  LOBYTE(v660) = 117;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v607);
  LOBYTE(v660) = 115;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v579);
  LOBYTE(v660) = 113;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v605);
  LOBYTE(v660) = 111;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v650);
  LOBYTE(v660) = 109;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v649);
  LOBYTE(v660) = 107;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v565);
  LOBYTE(v660) = 105;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v603);
  LOBYTE(v660) = 103;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v577);
  LOBYTE(v660) = 101;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v601);
  LOBYTE(v660) = 99;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v555);
  LOBYTE(v660) = 97;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v599);
  LOBYTE(v660) = 95;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v646);
  LOBYTE(v660) = 93;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v644);
  LOBYTE(v660) = 91;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v642);
  LOBYTE(v660) = 89;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v640);
  LOBYTE(v660) = 87;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v638);
  LOBYTE(v660) = 85;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v636);
  LOBYTE(v660) = 83;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v634);
  LOBYTE(v660) = 81;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v632);
  LOBYTE(v660) = 79;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v630);
  LOBYTE(v660) = 77;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v628);
  LOBYTE(v660) = 75;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v626);
  LOBYTE(v660) = 73;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v624);
  LOBYTE(v660) = 69;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v622);
  LOBYTE(v660) = 67;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v620);
  LOBYTE(v660) = 65;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v618);
  LOBYTE(v660) = 63;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v616);
  LOBYTE(v660) = 61;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v614);
  LOBYTE(v660) = 59;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v612);
  LOBYTE(v660) = 57;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v610);
  LOBYTE(v660) = 56;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v608);
  LOBYTE(v660) = 55;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v606);
  LOBYTE(v660) = 54;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v604);
  LOBYTE(v660) = 52;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v602);
  LOBYTE(v660) = 51;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v600);
  LOBYTE(v660) = 50;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v598);
  LOBYTE(v660) = 49;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v596);
  LOBYTE(v660) = 48;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v594);
  LOBYTE(v660) = 47;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v592);
  LOBYTE(v660) = 45;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v590);
  LOBYTE(v660) = 43;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v588);
  LOBYTE(v660) = 41;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v586);
  LOBYTE(v660) = 39;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v584);
  LOBYTE(v660) = 37;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v582);
  LOBYTE(v660) = 35;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v580);
  LOBYTE(v660) = 33;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v578);
  LOBYTE(v660) = 31;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v576);
  LOBYTE(v660) = 29;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v574);
  LOBYTE(v660) = 27;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v572);
  LOBYTE(v660) = 25;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v570);
  LOBYTE(v660) = 23;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v568);
  LOBYTE(v660) = 21;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v566);
  LOBYTE(v660) = 19;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v564);
  LOBYTE(v660) = 16;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v648);
  LOBYTE(v660) = 15;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v647);
  LOBYTE(v660) = 14;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v658);
  LOBYTE(v660) = 13;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v562);
  LOBYTE(v660) = 12;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v551);
  LOBYTE(v660) = 11;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v560);
  LOBYTE(v660) = 10;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v657);
  LOBYTE(v660) = 9;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v558);
  LOBYTE(v660) = 8;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v655);
  LOBYTE(v660) = 7;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v556);
  LOBYTE(v660) = 6;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v656);
  LOBYTE(v660) = 5;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v554);
  LOBYTE(v660) = 4;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v654);
  LOBYTE(v660) = 3;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v552);
  LOBYTE(v660) = 2;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v652);
  LOBYTE(v660) = 1;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v645);
  LOBYTE(v660) = 0;
  LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v653);
  v660 = -1;
  return LuaPlus::LuaObject::~LuaObject((LuaPlus::LuaObject *)&v659);
}

void __thiscall sub_877220(LuaPlus::LuaObject *this, const char *a2, int a3, int a4)
{
  LuaPlus::LuaObject *v4; // esi

  v4 = this;
  *(_DWORD *)lua_newuserdata(**((_DWORD **)this + 2), 4) = a3;
  LuaPlus::LuaObject::Register(v4, a2, (int (__cdecl *)(struct lua_State *))sub_877160, a4 + 1);
}