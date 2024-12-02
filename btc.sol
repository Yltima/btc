// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-IERC20Permit.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract MyToken is IERC20, IERC20Permit, Ownable, EIP712 {
    using SafeMath for uint256;

    string private _name;
    string private _symbol;
    uint8 public immutable decimals;
    uint256 private _totalSupply;

    string public tokenIconURI;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    mapping(address => uint256) private _nonces;

    constructor(
        string memory _tokenName,
        string memory _tokenSymbol,
        string memory _tokenIconURI
    ) Ownable(msg.sender) EIP712(_tokenName, "1") {
        _name = _tokenName;
        _symbol = _tokenSymbol;
        tokenIconURI = _tokenIconURI;
        decimals = 8;

        uint256 initialSupply = 1000000 * 10 ** uint256(decimals);
        _totalSupply = initialSupply;
        _balances[msg.sender] = initialSupply;
    }

    // Реализация функций IERC20
    function name() public view returns (string memory) {
        return _name;
    }

    function symbol() public view returns (string memory) {
        return _symbol;
    }

    function totalSupply() public view override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view override returns (uint256) {
        return _balances[account];
    }

    function transfer(address recipient, uint256 amount) public override returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) public view override returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public override returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {
        _transfer(sender, recipient, amount);
        uint256 currentAllowance = _allowances[sender][msg.sender];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        _approve(sender, msg.sender, currentAllowance - amount);
        return true;
    }

    function _transfer(address sender, address recipient, uint256 amount) internal {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        uint256 senderBalance = _balances[sender];
        require(senderBalance >= amount, "ERC20: transfer amount exceeds balance");

        _balances[sender] = senderBalance - amount;
        _balances[recipient] += amount;
        emit Transfer(sender, recipient, amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    // Реализация IERC20Permit
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public override {
        require(block.timestamp <= deadline, "ERC20Permit: expired deadline");

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                owner,
                spender,
                value,
                _nonces[owner]++,
                deadline
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "ERC20Permit: invalid signature");

        _approve(owner, spender, value);
    }

    function nonces(address owner) public view override returns (uint256) {
        return _nonces[owner];
    }

    function DOMAIN_SEPARATOR() public view override returns (bytes32) {
        return _domainSeparatorV4();
    }

    // Вспомогательная функция для получения данных токена
    function getTokenMetadata() public view returns (string memory, string memory, string memory) {
        return (_name, _symbol, tokenIconURI);
    }
}
