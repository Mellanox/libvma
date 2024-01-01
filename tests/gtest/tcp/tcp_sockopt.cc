/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <fstream>
#include <limits>
#include <stdexcept>
#include <tuple>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common/def.h"
extern struct gtest_configure_t gtest_conf;

struct reusable_cleanable_test_socket {
  int m_fd;
  reusable_cleanable_test_socket(int domain, int type, int protocol) {
    m_fd = socket(domain, type, protocol);
    EXPECT_GE(m_fd, 0) << "Unable to open the socket";
    int reuse = 1;
    auto result =
        setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    EXPECT_EQ(result, 0) << "setsockopt failed to set reuse addr";

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }
  explicit reusable_cleanable_test_socket(int fd) : m_fd{fd} {
    EXPECT_GE(m_fd, 0) << "Unable to open the socket";
  };
  ~reusable_cleanable_test_socket() { close(m_fd); }

  operator int() const { return m_fd; }
};

struct ipc {
  enum FifoDirection : size_t { ReadSide, WriteSide };
  int m_pipe[2];
  ipc() : m_pipe{-1, -1} {}

  ~ipc() { reset(); }
  void create() {
    if (pipe(m_pipe) != 0) {
      throw std::runtime_error("Pipe not created");
    }
  }
  void reset() {
    if (m_pipe[ReadSide] != -1) {
      close(m_pipe[ReadSide]);
    }
    if (m_pipe[WriteSide] != -1) {
      close(m_pipe[WriteSide]);
    }
  }
  bool wait_peer() {
    if (m_pipe[ReadSide] == -1) {
      return false;
    }

    if (m_pipe[WriteSide] != -1) {
      if (close(m_pipe[WriteSide]) != 0) {
        return false;
      }
      m_pipe[WriteSide] = -1;
    }

    char buffer[16];
    auto result = read(m_pipe[ReadSide], buffer, 1) == 1;
    return result;
  }

  bool signal_to_peer() {
    if (m_pipe[WriteSide] == -1) {
      return false;
    }

    if (m_pipe[ReadSide] != -1) {
      if (close(m_pipe[ReadSide]) != 0) {
        return false;
      }
      m_pipe[ReadSide] = -1;
    }

    return write(m_pipe[WriteSide], "X", 1) == 1;
  }
};

using sockopt_parameters = std::tuple<int, int, int, int>;
using tcp_sockopt_positive = testing::TestWithParam<sockopt_parameters>;
/*
 * @test tcp_sockopt_positive.set_and_get_value
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt/getsockopt level, optname,
 *    and value.
 *    The test sets the value and checks the value with the setsockopt/getsockopt syscalls.
 * @details
 */
TEST_P(tcp_sockopt_positive, set_and_get_value) {
  int socket_domain, level, optname, value;
  std::tie(socket_domain, level, optname, value) = GetParam();

  auto fd = reusable_cleanable_test_socket(socket_domain, static_cast<int>(SOCK_STREAM), 0);
  EXPECT_GE(fd, 0) << "socket syscall failed";
  auto result = setsockopt(fd, level, optname, &value, sizeof(value));
  EXPECT_EQ(result, 0) << "setsockopt failed to set the value";

  int actual_value = -1;
  socklen_t actual_len = sizeof(actual_value);
  result = getsockopt(fd, level, optname, &actual_value, &actual_len);
  EXPECT_EQ(result, 0) << "getsockopt failed to get the value";
  EXPECT_EQ(actual_len, sizeof(actual_value))
      << "Got unexpected size of agument";
  ASSERT_EQ(actual_value, value);
}

/* The valid ranges are dictated by the Linux Kernel and not the TCP RFC 9293
 * There may be multiple instantiations of the tcp_sockopt_positive class and
 * it's test cases.
 */
INSTANTIATE_TEST_CASE_P(
    keep_alive, tcp_sockopt_positive,
    testing::Values(std::make_tuple(AF_INET, SOL_SOCKET, SO_KEEPALIVE, 1),
                    std::make_tuple(AF_INET, SOL_SOCKET, SO_KEEPALIVE, 0),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE, 1),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE,
                                    std::numeric_limits<int16_t>::max()),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, 1),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL,
                                    std::numeric_limits<int16_t>::max()),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, 1),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT,
                                    std::numeric_limits<int8_t>::max()),
                    std::make_tuple(AF_INET6, SOL_SOCKET, SO_KEEPALIVE, 1),
                    std::make_tuple(AF_INET6, SOL_SOCKET, SO_KEEPALIVE, 0),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE, 1),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE,
                                    std::numeric_limits<int16_t>::max()),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, 1),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL,
                                    std::numeric_limits<int16_t>::max()),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, 1),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT,
                                    std::numeric_limits<int8_t>::max())));

using tcp_setsockopt_negative = testing::TestWithParam<sockopt_parameters>;
/*
 * @test tcp_setsockopt_negative.set_invalid_value
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt/getsockopt level, optname,
 *    and value.
 *    The test attempts setting an invalid value via setsockopt syscall.
 * @details
 */
TEST_P(tcp_setsockopt_negative, set_invalid_value) {
  int socket_domain, level, optname, value;
  std::tie(socket_domain, level, optname, value) = GetParam();

  auto fd = reusable_cleanable_test_socket(socket_domain, SOCK_STREAM, 0);
  EXPECT_GE(fd, 0) << "socket syscall failed to setup a socket";

  auto result = setsockopt(fd, level, optname, &value, sizeof(value));
  EXPECT_NE(result, 0) << "setsockopt didn't fail to set the value";
}

/* The valid ranges are dictated by the Linux Kernel and not the TCP RFC 9293
 * There may be multiple instantiations of the tcp_setsockopt_negative class and
 * it's test cases.
 */
INSTANTIATE_TEST_CASE_P(
    keep_alive, tcp_setsockopt_negative,
    testing::Values(std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE, -1),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE,
                                    std::numeric_limits<int16_t>::max() + 1),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, -1),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL, 0),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL,
                                    std::numeric_limits<int16_t>::max() + 1),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, -1),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT, 0),
                    std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT,
                                    std::numeric_limits<int8_t>::max() + 1),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE, -1),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPIDLE,
                                    std::numeric_limits<int16_t>::max() + 1),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, -1),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL, 0),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPINTVL,
                                    std::numeric_limits<int16_t>::max() + 1),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, -1),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT, 0),
                    std::make_tuple(AF_INET6, IPPROTO_TCP, TCP_KEEPCNT,
                                    std::numeric_limits<int8_t>::max() + 1)));

using getscokopt_params = std::tuple<int, int, int, const char *>;
using tcp_sockopt_default = testing::TestWithParam<getscokopt_params>;
/*
 * @test tcp_sockopt_default.matches_the_value_in_the_file
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt/getsockopt level, optname,
 *    and file path containing the default value.
 *    The test verifies that the default value of a newly creates socket match file.
 * @details
 */
TEST_P(tcp_sockopt_default, matches_the_value_in_the_file) {
  int socket_domain, level, optname;
  const char *file_path;
  std::tie(socket_domain, level, optname, file_path) = GetParam();

  auto fd = reusable_cleanable_test_socket(socket_domain, SOCK_STREAM, 0);
  EXPECT_GE(fd, 0) << "socket syscall failed to setup a socket";

  /* Get the value via getsockopt */
  int getsockopt_value = -1;
  socklen_t actual_len = sizeof(getsockopt_value);
  auto result =
      getsockopt(fd, level, optname, &getsockopt_value, &actual_len);
  EXPECT_EQ(result, 0) << "getsockopt failed";
  EXPECT_EQ(actual_len, sizeof(getsockopt_value))
      << "Got unexpected size of agument";

  /* Get the value from the file */
  int file_value = -1;
  EXPECT_TRUE(bool(std::ifstream{file_path} >> file_value))
      << "Failed reading the file";

  ASSERT_EQ(getsockopt_value, file_value)
      << "The values in the file and the getsockopt differ";
  close(fd);
}

INSTANTIATE_TEST_CASE_P(
    keep_alive, tcp_sockopt_default,
    testing::Values(
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPIDLE,
                        "/proc/sys/net/ipv4/tcp_keepalive_time"),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPINTVL,
                        "/proc/sys/net/ipv4/tcp_keepalive_intvl"),
        std::make_tuple(AF_INET, IPPROTO_TCP, TCP_KEEPCNT,
                        "/proc/sys/net/ipv4/tcp_keepalive_probes")));

using setsockopt_param = std::tuple<int, int, int>;
class tcp_with_fifo : public testing::TestWithParam<setsockopt_param> {
protected:
  ipc m_ipc_server_to_client{};

  void SetUp() override { m_ipc_server_to_client.create(); }

  void TearDown() override { m_ipc_server_to_client.reset(); }
};

/*
 * @test tcp_with_fifo.set_listen_get_accept_socket
 * @brief
 *    This is a parameterized test requiring sockopt_parameters. The parameters in the
 *    sockopt_parameters are the socket domain, setsockopt level, optname, and value.
 *    The test verifies that the set value is inherited by the accepted socket.
 * @details
 */
TEST_P(tcp_with_fifo, accepted_socket_inherits_the_setsockopt_param) {
  int level, optname, value;
  std::tie(level, optname, value) = GetParam();
  pid_t pid = fork();

  if (pid > 0) { // Parent process (the "server" process)

    auto listen_fd = reusable_cleanable_test_socket(
        gtest_conf.server_addr.sin_family, SOCK_STREAM, 0);
    EXPECT_GE(listen_fd, 0) << "socket syscall failed to setup a socket";

    EXPECT_EQ(bind(listen_fd, (struct sockaddr *)&gtest_conf.server_addr,
                   sizeof(gtest_conf.server_addr)),
              0);
    EXPECT_EQ(listen(listen_fd, 5), 0);

    auto result = setsockopt(listen_fd, level, optname, &value, sizeof(value));
    EXPECT_EQ(result, 0) << "setsockopt failed to set the value";

    m_ipc_server_to_client.signal_to_peer();

    reusable_cleanable_test_socket accepted_fd{accept(listen_fd, nullptr, 0)};
    EXPECT_GE(accepted_fd, 0) << "Invalid accepted_fd";

    int actual_value = -1;
    socklen_t actual_len = sizeof(actual_value);
    result = getsockopt(accepted_fd, level, optname, &actual_value,
                        &actual_len);
    m_ipc_server_to_client.signal_to_peer();

    int status;
    EXPECT_EQ(pid, wait(&status));
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(result, 0) << "getsockopt failed to get the value";
    EXPECT_EQ(actual_len, sizeof(actual_value))
        << "Got unexpected size of agument";

    ASSERT_EQ(actual_value, value);
  } else if (pid == 0) { // Child process (the "client" process)
    auto client_fd = reusable_cleanable_test_socket(
        gtest_conf.client_addr.sin_family, SOCK_STREAM, 0);
    EXPECT_GE(client_fd, 0) << "socket syscall failed to setup a socket";
    EXPECT_EQ(bind(client_fd, (struct sockaddr *)&gtest_conf.client_addr,
                   sizeof(gtest_conf.client_addr)),
              0);
    m_ipc_server_to_client.wait_peer();

    auto result = connect(client_fd, (struct sockaddr *)&gtest_conf.server_addr,
                          sizeof(gtest_conf.server_addr));
    EXPECT_EQ(result, 0);

    m_ipc_server_to_client.wait_peer();

    // This exit stops the process from inerfering with other tests.
    exit(testing::Test::HasFailure());
  } else {
    FAIL() << "Fork failed";
  }
}

INSTANTIATE_TEST_CASE_P(
    keep_alive, tcp_with_fifo,
    testing::Values(
        std::make_tuple(SOL_SOCKET, SO_KEEPALIVE, 0),
        std::make_tuple(SOL_SOCKET, SO_KEEPALIVE, 1),
        std::make_tuple(static_cast<int>(IPPROTO_TCP), TCP_KEEPIDLE, 1234),
        std::make_tuple(static_cast<int>(IPPROTO_TCP), TCP_KEEPINTVL, 12345),
        std::make_tuple(static_cast<int>(IPPROTO_TCP), TCP_KEEPCNT, 123)));
