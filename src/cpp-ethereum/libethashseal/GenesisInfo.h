/*
        This file is part of cpp-ethereum.

        cpp-ethereum is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        cpp-ethereum is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file GenesisInfo.h
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#pragma once

#include <string>
#include <libdevcore/FixedHash.h>
#include <libethcore/Common.h>

namespace dev
{
namespace eth
{

/// The network id.
enum class Network
{
	//Olympic = 0,			///< Normal Olympic chain.
	MainNetwork = 1,		///< Normal Frontier/Homestead/DAO/EIP150/EIP158/Metropolis chain.
	//Morden = 2,			///< Normal Morden chain.
	Ropsten = 3,			///< New Ropsten Test Network
	MainNetworkTest = 69,	///< MainNetwork rules but without genesis accounts (for transaction tests).
	TransitionnetTest = 70,	///< Normal Frontier/Homestead/DAO/EIP150/EIP158 chain without all the premine.
	FrontierTest = 71,		///< Just test the Frontier-era characteristics "forever" (no Homestead portion).
	HomesteadTest = 72,		///< Just test the Homestead-era characteristics "forever" (no Frontier portion).
	EIP150Test = 73,		///< Homestead + EIP150 Rules active from block 0 For BlockchainTests
	EIP158Test = 74,		///< Homestead + EIP150 + EIP158 Rules active from block 0
	MetropolisTest = 75,    ///< All fork rules + Metropolis active from block 0
	Special = 0xff,			///< Something else.
	omnixMainNetwork = 9,    ///< OMNIX Homestead + EIP150 + EIP158 Rules active from block 0 to enum class Network
	omnixTestNetwork = 10
};

std::string const& genesisInfo(Network _n);
h256 const& genesisStateRoot(Network _n);

}
}
