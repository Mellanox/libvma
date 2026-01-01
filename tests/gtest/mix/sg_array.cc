/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "common/def.h"

#include "mix_base.h"

#include "src/vma/ib/base/verbs_extra.h"
#include "src/vma/util/sg_array.h"

class sg_array_test : public mix_base {
public:
	struct ibv_sge*	sge0;
	struct ibv_sge	sge1;
	struct ibv_sge	sge2[2];
	struct ibv_sge	sge3[3];
	sg_array_test()
	{
		sge0 = NULL;

		sge1.addr = (uint64_t)"0123456789";
		sge1.length = 10;

		sge2[0].addr = (uint64_t)"0123456789";
		sge2[0].length = 10;
		sge2[1].addr = (uint64_t)"0123456789";
		sge2[1].length = 10;

		sge3[0].addr = (uint64_t)"0123456789";
		sge3[0].length = 10;
		sge3[1].addr = (uint64_t)"0123456789";
		sge3[1].length = 10;
		sge3[2].addr = (uint64_t)"0123456789";
		sge3[2].length = 10;
	}

};
//! Tests for constructor
TEST_F(sg_array_test, sga_ctr)
{
	sg_array	sa0(sge0,0);
	EXPECT_EQ(-1, sa0.get_num_sge());
	EXPECT_EQ(0, sa0.length());

	sg_array	sa1(&sge1,1);
	EXPECT_EQ(1, sa1.get_num_sge());
	EXPECT_EQ(10, sa1.length());

	sg_array	sa2(sge2,2);
	EXPECT_EQ(2, sa2.get_num_sge());
	EXPECT_EQ(20, sa2.length());

	sg_array	sa3(sge3,3);
	EXPECT_EQ(3, sa3.get_num_sge());
	EXPECT_EQ(30, sa3.length());

}

//! Tests for relative index
//
TEST_F(sg_array_test, sga_index_0)
{
	sg_array sa0(sge0, 0);
	EXPECT_EQ(NULL, sa0.get_data(0));

	sg_array sa1(&sge1, 1);
	EXPECT_EQ(NULL, sa0.get_data(0));
}

//! Tests for minimum bound
//
TEST_F(sg_array_test, sga_min_bound)
{
	sg_array sa0(sge0, 0);
	int	len=-1;
	EXPECT_EQ(NULL, sa0.get_data(&len));

	sg_array sa1(&sge1, 1);
	EXPECT_EQ(NULL, sa1.get_data(&len));
}

//! Test for maximum bound
//
TEST_F(sg_array_test, sga_max_bound)
{
	sg_array sa0(sge0, 0);
	int len = 1;
	EXPECT_EQ(NULL, sa0.get_data(&len));

	sg_array sa1(&sge1, 1);
	len = 11;
	uint8_t *p = sa1.get_data(&len);
	EXPECT_EQ(len, 10);
	EXPECT_EQ((uint64_t)p, sge1.addr);

	p = sa1.get_data(&len);
	EXPECT_EQ((uint64_t)p, NULL);
}

//! Tests for in_bound
//
TEST_F(sg_array_test, sga_in_bound)
{
	sg_array sa1(&sge1, 1);

	int len = 5;
	uint8_t *p = sa1.get_data(&len);

	EXPECT_EQ(len, 5);
	EXPECT_EQ((uint64_t)p, sge1.addr);

	len = 10;
	p = sa1.get_data(&len);

	EXPECT_EQ(len, 5);
	EXPECT_EQ(*p, '5');
}

//! Tests for in_bound
//
TEST_F(sg_array_test, sga_in_bound_multi_sge)
{
	sg_array sa3(sge3, 3);

	int len = 5;
	uint8_t *p = sa3.get_data(&len);

	EXPECT_EQ(len, 5);
	EXPECT_EQ((uint64_t)p, sge3[0].addr);

	len = 10;
	p = sa3.get_data(&len);

	EXPECT_EQ(len, 5);
	EXPECT_EQ(*p, '5');

	len = 15;
	p = sa3.get_data(&len);

	EXPECT_EQ(len, 10);
	EXPECT_EQ((uint64_t)p, sge3[1].addr);

	len = 10;
	p = sa3.get_data(&len);

	EXPECT_EQ(len, 10);
	EXPECT_EQ((uint64_t)p, sge3[2].addr);
}


