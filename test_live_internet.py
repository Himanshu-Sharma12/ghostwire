"""Real live internet test script using the generated GhostWire SDK."""

from live_sdk.client import ApiClient

def main():
    print("🚀 Running REAL LIVE test against https://dummyjson.com across the internet...")
    
    # ApiClient automatically has base_url="https://dummyjson.com" and pre-configured Bearer token!
    client = ApiClient()

    # 1. Real Live Call: Fetch authenticated user
    print("\n[1/4] Calling LIVE client.get_auth_me()...")
    me = client.get_auth_me()
    print("   -> Authenticated User:", me.get("firstName"), me.get("lastName"), f"({me.get('email')})")
    print("   -> Role:", me.get("role"), "| Gender:", me.get("gender"))

    # 2. Real Live Call: Fetch Product #5
    print("\n[2/4] Calling LIVE client.get_products_by_productId(productId=5)...")
    p5 = client.get_products_by_productId(productId=5)
    print("   -> Product #5 Title:", p5.get("title"))
    print("   -> Price: $" + str(p5.get("price")), "| Brand:", p5.get("brand"))

    # 3. Real Live Call: Search Products
    print("\n[3/4] Calling LIVE client.get_products_search(q='laptop', limit=2)...")
    search_res = client.get_products_search(q="laptop", limit=2)
    items = search_res.get("products", [])
    print(f"   -> Found {len(items)} items matching query 'laptop':")
    for item in items:
        print("      *", item.get("title"), f"(${item.get('price')})")

    # 4. Real Live Call: Create product on live server
    print("\n[4/4] Calling LIVE client.create_products_add(payload=...)...")
    created = client.create_products_add(payload={"title": "GhostWire Autonomous Agent v1.0", "price": 499.0, "category": "developer-tools"})
    print("   -> Response from Live Server:", created.get("id"), "| Title:", created.get("title"))

    print("\n🎉 100% REAL LIVE INTERNET TEST COMPLETE! ZERO MOCKS!")

if __name__ == "__main__":
    main()
