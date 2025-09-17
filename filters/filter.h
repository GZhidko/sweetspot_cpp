#pragma once
template<typename Header>
struct Filter { bool operator()(const Header&) { return true; } };
