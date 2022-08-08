// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;
contract NeonDistributor {

    mapping(string => address payable) recipients;
    string[] names;

    function set_address(string calldata _name, address payable _address) public {
        require(recipients[_name] == 0x0000000000000000000000000000000000000000);
        recipients[_name] = _address;
        names.push(_name);
    }

    function get_address(string calldata _name) public view returns (address) {
        return recipients[_name];
    }

    function distribute_value () public payable {
        uint val = msg.value / names.length;
        for (uint i = 0; i < names.length; i++) {
            recipients[ names[i] ].transfer(val);
        }
    }
}
