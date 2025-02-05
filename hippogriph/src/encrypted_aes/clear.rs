pub fn clear_s_box_boyar(y : &Vec<bool>) -> Vec<bool> {
    assert_eq!(y.len(), 22);
    let t2 = y[12] & y[15];
    let t3 = y[3] & y[6] ;
    let t4 = t3 ^ t2;
    let t5 = y[4] & y[0] ;
    let t6 = t5 ^ t2 ;
    let t7 = y[13] & y[16];
    let t8 = y[5] & y[1] ;
    let t9 = t8 ^ t7 ;
    let t10 = y[2] & y[7];
    let t11 = t10 ^ t7 ;
    let t12 = y[9] & y[11] ;
    let t13 = y[14] & y[17];
    let t14 = t13 ^ t12 ;
    let t15 = y[8] & y[10];
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y[20];
    let t22 = t18 ^ y[19];
    let t23 = t19 ^ y[21];
    let t24 = t20 ^ y[18];
    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41 ;
    let z0 = t44 & y[15];
    let z1 = t37 & y[6] ;
    let z2 = t33 & y[0] ;
    let z3 = t43 & y[16];
    let z4 = t40 & y[1] ;
    let z5 = t29 & y[7] ;
    let z6 = t42 & y[11];
    let z7 = t45 & y[17] ;
    let z8 = t41 & y[10] ;
    let z9 = t44 & y[12];
    let z10 = t37 & y[3];
    let z11 = t33 & y[4];
    let z12 = t43 & y[13];
    let z13 = t40 & y[5];
    let z14 = t29 & y[2];
    let z15 = t42 & y[9];
    let z16 = t45 & y[14];
    let z17 = t41 & y[8];
    vec![z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15, z16, z17]    
}



pub fn clear_pre_circuit(x : &Vec<bool>)->Vec<bool>{
    assert_eq!(x.len(), 8);
    let y14 = x[3] ^ x[5];
    let y13 = x[0] ^ x[6];
    let y9 = x[0] ^ x[3];
    let y8 = x[0] ^ x[5];
    let t0 = x[1] ^ x[2];
    let y1 = t0 ^ x[7];
    let y4 = y1 ^ x[3];
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x[0];
    let y5 = y1 ^ x[6];
    let y3 = y5 ^ y8;
    let t1 = x[4] ^ y12;
    let y15 = t1 ^ x[5];
    let y20 = t1 ^ x[1];
    let y6 = y15 ^ x[7];
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x[7] ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x[0] ^ y16;
    vec![x[7], y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15, y16, y17, y18, y19, y20, y21]
}


pub fn clear_post_circuit(x : &Vec<bool>)->Vec<bool>{
    let t46 = x[15] ^ x[16];
    let t47 = x[10] ^ x[11];
    let t48 = x[5] ^ x[13];
    let t49 = x[9] ^ x[10];
    let t50 = x[2] ^ x[12];
    let t51 = x[2] ^ x[5];
    let t52 = x[7] ^ x[8];
    let t53 = x[0] ^ x[3];
    let t54 = x[6] ^ x[7];
    let t55 = x[16] ^ x[17];
    let t56 = x[12] ^ t48;
    let t57 = t50 ^ t53;
    let t58 = x[4] ^ t46;
    let t59 = x[3] ^ t54;
    let t60 = t46 ^ t57;
    let t61 = x[14] ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = x[4] ^ t59;
    let t65 = t61 ^ t62;
    let t66 = x[1] ^ t63;
    let y0 = t59 ^ t63;
    let y6 = !(t56 ^ t62);
    let y7 = !(t48 ^ t60);
    let t67 = t64 ^ t65;
    let y3 = t53 ^ t66;
    let y4 = t51 ^ t66;
    let y5 = t47 ^ t65;
    let y1 = !(t64 ^ y3);
    let y2 = !(t55 ^ t67);
    vec![y0, y1, y2, y3, y4, y5, y6, y7]
}




pub fn clear_mixcolumns(x : &Vec<bool>) -> Vec<bool>{
    assert_eq!(x.len(), 32);
    let t0 = x[0] ^ x[8];
    let t1 = x[16] ^ x[24];
    let t2 = x[1] ^ x[9];
    let t3 = x[17] ^ x[25];
    let t4 = x[2] ^ x[10];
    let t5 = x[18] ^ x[26];
    let t6 = x[3] ^ x[11];
    let t7 = x[19] ^ x[27];
    let t8 = x[4] ^ x[12];
    let t9 = x[20] ^ x[28];
    let t10 = x[5] ^ x[13];
    let t11 = x[21] ^ x[29];
    let t12 = x[6] ^ x[14];
    let t13 = x[22] ^ x[30];
    let t14 = x[23] ^ x[31];
    let t15 = x[7] ^ x[15];
    let t16 = x[8] ^ t1;
    let y0 = t15 ^ t16;
    let t17 = x[7] ^ x[23];
    let t18 = x[24] ^ t0;
    let y16 = t14 ^ t18;
    let t19 = t1 ^ y16;
    let y24 = t17 ^ t19;
    let t20 = x[27] ^ t14;
    let t21 = t0 ^ y0;
    let y8 = t17 ^ t21;
    let t22 = t5 ^ t20;
    let y19 = t6 ^ t22;
    let t23 = x[11] ^ t15;
    let t24 = t7 ^ t23;
    let y3 = t4 ^ t24;
    let t25 = x[2] ^ x[18];
    let t26 = t17 ^ t25;
    let t27 = t9 ^ t23;
    let t28 = t8 ^ t20;
    let t29 = x[10] ^ t2;
    let y2 = t5 ^ t29;
    let t30 = x[26] ^ t3;
    let y18 = t4 ^ t30;
    let t31 = x[9] ^ x[25];
    let t32 = t25 ^ t31;
    let y10 = t30 ^ t32;
    let y26 = t29 ^ t32;
    let t33 = x[1] ^ t18;
    let t34 = x[30] ^ t11;
    let y22 = t12 ^ t34;
    let t35 = x[14] ^ t13;
    let y6 = t10 ^ t35;
    let t36 = x[5] ^ x[21];
    let t37 = x[30] ^ t17;
    let t38 = x[17] ^ t16;
    let t39 = x[13] ^ t8;
    let y5 = t11 ^ t39;
    let t40 = x[12] ^ t36;
    let t41 = x[29] ^ t9;
    let y21 = t10 ^ t41;
    let t42 = x[28] ^ t40;
    let y13 = t41 ^ t42;
    let y29 = t39 ^ t42;
    let t43 = x[15] ^ t12;
    let y7 = t14 ^ t43;
    let t44 = x[14] ^ t37;
    let y31 = t43 ^ t44;
    let t45 = x[31] ^ t13;
    let y15 = t44 ^ t45;
    let y23 = t15 ^ t45;
    let t46 = t12 ^ t36;
    let y14 = y6 ^ t46;
    let t47 = t31 ^ t33;
    let y17 = t19 ^ t47;
    let t48 = t6 ^ y3;
    let y11 = t26 ^ t48;
    let t49 = t2 ^ t38;
    let y25 = y24 ^ t49;
    let t50 = t7 ^ y19;
    let y27 = t26 ^ t50;
    let t51 = x[22] ^ t46;
    let y30 = t11 ^ t51;
    let t52 = x[19] ^ t28;
    let y20 = x[28] ^ t52;
    let t53 = x[3] ^ t27;
    let y4 = x[12] ^ t53;
    let t54 = t3 ^ t33;
    let y9 = y8 ^ t54;
    let t55 = t21 ^ t31;
    let y1 = t38 ^ t55;
    let t56 = x[4] ^ t17;
    let t57 = x[19] ^ t56;
    let y12 = t27 ^ t57;
    let t58 = x[3] ^ t28;
    let t59 = t17 ^ t58;
    let y28 = x[20] ^ t59;
    vec![y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15, y16, y17, y18, y19, y20, y21, y22, y23, y24, y25, y26, y27, y28, y29, y30, y31]
}



pub fn clear_sub_bytes(x : u64) -> u64{
    assert!(x < 256);
    let s_box : Vec<u64> = vec![
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ];
    s_box[x as usize]
}