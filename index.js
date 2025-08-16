require("dotenv").config();
const path = require("path");

const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
const app = express();
var admin = require("firebase-admin");

app.use(express.json());
app.use(cors());


const serviceAccountPath = path.resolve(process.env.FB_SERVICE_KEY_PATH);
const serviceAccount = require(serviceAccountPath);



admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const port = process.env.PORT || 3000;

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.zkxiogp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({ message: "Unauthorized access." });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;

    next();
  } catch (error) {
    return res.status(401).send({ message: "Unauthorized access." });
  }
};

const verifyFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded; // includes uid, email, custom claims
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

async function run() {
  try {
    // await client.connect();
    const havenSpaceDB = client.db("HavenSpaceDB");
    const userCollection = havenSpaceDB.collection("user");
    const propertiesCollection = havenSpaceDB.collection("properties");
    const reviewsCollection = havenSpaceDB.collection("reviews");

    app.post("/auth/register", async (req, res) => {
      const userData = req.body;

      const result = await userCollection.insertOne(userData);
      res.send(result);
    });

    app.get("/auth/users/:id", async (req, res) => {
      const id = req.params.id;
      const result = await userCollection.findOne({ uid: id });
      res.send(result);
    });

    app.get("/api/user-role/:uid", verifyFirebaseToken, async (req, res) => {
      try {
        const uid = req.params.uid;
        const user = await userCollection.findOne({ uid: uid });

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        res.send({ role: user.role });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    app.post("/api/properties", async (req, res) => {
      const property = req.body;
      const result = await propertiesCollection.insertOne(property);
      res.send(result);
    });

    app.get("/api/properties", async (req, res) => {
      const result = await propertiesCollection.find().toArray();
      res.send(result);
    });

    app.get("/api/home-properties", async (req, res) => {
      const result = await propertiesCollection
        .find()
        .limit(6)
        .sort({ createdAt: -1 })
        .toArray();
      res.send(result);
    });


    app.get('/properties/search', async (req, res) => {
      try {
        const { location, propertyType, priceRange } = req.query;

        // Build base query
        const query = {
          adminApproval: "true",
          availability: "Available"
        };

        // Location filter (case-insensitive partial match)
        if (location) {
          query.location = {
            $regex: location.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'),
            $options: 'i'
          };
        }

        // Property type filter
        if (propertyType && propertyType !== "Property Type") {
          query.propertyType = propertyType;
        }

        // Price range filter
        if (priceRange && priceRange !== "Price Range") {
          let minPrice, maxPrice;

          if (priceRange === "$600k+") {
            minPrice = 600000;
            maxPrice = Infinity;
          } else {
            const rangeParts = priceRange.replace(/\$/g, '').replace(/k/g, '000').split(' - ');
            minPrice = parseInt(rangeParts[0]);
            maxPrice = parseInt(rangeParts[1]);
          }

          query.$and = [
            { maxPrice: { $gte: minPrice } },
            { minPrice: { $lte: maxPrice } }
          ];
        }

        const results = await propertiesCollection.find(query).toArray();
        res.json(results);

      } catch (err) {
        console.error('Search error:', err);
        res.status(500).json({
          error: 'Server error',
          message: err.message
        });
      }
    });

    app.get("/api/all-properties", verifyFirebaseToken, async (req, res) => {
      const result = await propertiesCollection
        .find({ adminApproval: "true" })
        .toArray();
      res.send(result);
    });

    app.get("/api/properties", verifyFirebaseToken, async (req, res) => {
      try {
        const agentUID = req.query.agentUID; // grab agentId from query string

        if (!agentUID) {
          return res.status(400).send({ message: "agentUID is not provided." });
        }

        const result = await propertiesCollection
          .find({ creatorUID: agentUID })
          .toArray();
        res.status(200).send(result);
      } catch (error) {
        console.error("Error fetching properties:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    app.patch("/api/properties", async (req, res) => {
      const { id, uid } = req.query; // Get id and uid from query string
      const updateData = req.body; // New data to update

      // Validate presence of id and uid
      if (!id || !uid) {
        return res.status(400).send({ message: "Missing id or uid in query." });
      }

      try {
        const filter = {
          _id: new ObjectId(id),
          agentId: uid, // Ensures the property belongs to the agent
        };

        const update = {
          $set: updateData,
        };

        const result = await propertiesCollection.updateOne(filter, update);

        if (result.modifiedCount === 0) {
          return res.status(404).send({
            message: "No matching property found or no changes made.",
          });
        }

        res.status(200).send({ message: "Property updated successfully." });
      } catch (error) {
        console.error("PATCH error:", error);
        res.status(500).send({ message: "Server error." });
      }
    });

    app.get("/api/properties/:id", verifyFirebaseToken, async (req, res) => {
      const id = req.params.id;
      const result = await propertiesCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    app.patch("/api/properties/:id", async (req, res) => {
      const id = req.params.id;
      const updateData = req.body;

      try {
        const query = { _id: new ObjectId(id) };
        const update = { $set: updateData };

        const result = await propertiesCollection.updateOne(query, update);

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .send({ error: "Property not found or already updated" });
        }

        res.send({ success: true, message: "Property updated successfully" });
      } catch (error) {
        console.error("PATCH error:", error);
        res.status(500).json({ error: "Server error" });
      }
    });

    app.delete("/api/properties/:id", async (req, res) => {
      const id = req.params.id;

      try {
        const result = await propertiesCollection.deleteOne({
          _id: new ObjectId(id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).send({ message: "Property not found" });
        }

        res.send({ success: true, message: "Property deleted successfully" });
      } catch (error) {
        console.error("Delete error:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // ||||||||||||||||||||||||||||||payment apis ||||||||||||||||||||||||||||||||||||||||||||
    app.post("/api/create-payment-intent", async (req, res) => {
      try {
        const { amount, propertyId, buyerId, agentId } = req.body;

        // Validate required fields
        if (!propertyId || !buyerId || !agentId || !amount) {
          return res.status(400).json({ error: "Missing required fields" });
        }

        const paymentIntent = await stripe.paymentIntents.create({
          amount: Math.round(parseFloat(amount) * 100),
          currency: "usd",
          payment_method_types: ["card"],
          metadata: {
            // MUST match webhook expectations
            propertyId,
            buyerId,
            agentId,
            amount,
            currency: "usd",
          },
        });

        res.json({
          clientSecret: paymentIntent.client_secret,
          paymentIntentId: paymentIntent.id,
        });
      } catch (err) {
        console.error("Payment intent error:", err);
        res.status(500).json({ error: "Payment processing failed" });
      }
    });

    app.post("/api/payment/create-checkout-session", async (req, res) => {
      const { offer } = req.body;

      if (!offer) {
        return res.status(400).json({ error: "Offer data missing" });
      }

      try {
        const amount = offer.offerDetails.amount * 100;
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: {
                  name: `Offer for ${offer.property.title}`,
                  description: offer.property.location,
                  images: offer.property.image ? [offer.property.image] : [],
                },
                unit_amount: amount,
              },
              quantity: 1,
            },
          ],
          mode: "payment",
          success_url: `http://localhost:5173/payment-success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `http://localhost:5173/property/${offer.property._id}`,

          metadata: {
            offerId: offer._id,
            propertyId: offer.property._id,
            agentId: offer.agentId,
          },
        });

        res.json({ url: session.url });
      } catch (err) {
        console.error("Stripe error:", err);
        res.status(500).json({ error: "Stripe session creation failed" });
      }
    });

    app.post(
      "/stripe-webhook",
      express.raw({ type: "application/json" }),
      async (req, res) => {
        const sig = req.headers["stripe-signature"];
        let event;

        try {
          event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
          );
        } catch (err) {
          console.error(
            "⚠️ Webhook signature verification failed:",
            err.message
          );
          return res.status(400).send(`Webhook Error: ${err.message}`);
        }

        // Handle successful payments
        if (event.type === "checkout.session.completed") {
          const session = event.data.object;
          console.log(session);

          const { propertyId, offerId, agentId } = session.metadata;

          try {
            await propertiesCollection.updateOne(
              { _id: new ObjectId(propertyId) },
              {
                $set: {
                  soldStatus: "true",
                  availability: "Sold",
                  soldDetails: {
                    soldPrice: session.amount_total / 100,
                    soldDate: new Date(),
                    buyerId: session.customer_email, // or attach UID if passed
                    transactionId: session.payment_intent,
                  },
                },
              }
            );
          } catch (err) {
            console.error("Error updating property after checkout:", err);
          }
        }

        res.json({ received: true });
      }
    );

    app.get("/api/payment/verify", verifyFirebaseToken, async (req, res) => {
      const { session_id } = req.query;

      if (!session_id) {
        return res.json({ verified: false, error: "Session ID required" });
      }

      try {
        const session = await stripe.checkout.sessions.retrieve(session_id);

        if (session.payment_status === "paid") {
          return res.json({
            verified: true,
            offerId: session.metadata?.offerId,
            amount: session.amount_total / 100,
          });
        }

        return res.json({ verified: false });
      } catch (err) {
        console.error("Verification error:", err);
        res.json({ verified: false, error: "Payment verification failed" });
      }
    });

    app.patch("/api/property/:id", async (req, res) => {
      const id = req.params.id;
      const updateData = req.body;

      try {
        const result = await propertiesCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Property not found" });
        }

        res.send({ message: "Property updated successfully" });
      } catch (error) {
        console.error("Error updating property:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });

    app.post("/api/reviews", async (req, res) => {
      const review = req.body;

      try {
        const result = await reviewsCollection.insertOne(review);
        res.send(result);
      } catch (err) {
        res.status(500).send({ error: "Failed to add review" });
      }
    });

    app.get("/api/property-reviews", verifyFirebaseToken, async (req, res) => {
      const result = await reviewsCollection
        .find({ reviewFor: "property" })
        .sort({ postedAt: -1 })
        .toArray();
      res.send(result);
    });
    app.get("/api/property-reviews/:userUID", verifyFirebaseToken, async (req, res) => {
      const userUID = req.params.userUID;
      const result = await reviewsCollection
        .find({ reviewerUID: userUID })
        .sort({ postedAt: -1 })
        .toArray();
      res.send(result);
    });

    app.get("/api/reviews", async (req, res) => {
      const propertyId = req.query.propertyId;
      const reviewFor = req.query.reviewFor;

      try {
        if (propertyId) {
          const result = await reviewsCollection
            .find({
              propertyId: propertyId,
            })
            .limit(5)
            .sort({
              postedAt: -1,
            })
            .toArray();
          res.send(result);
        }
        if (reviewFor) {
          const result = await reviewsCollection
            .find({ reviewFor: "website" })
            .sort({
              postedAt: -1,
            })
            .limit(5)
            .toArray();
          res.send(result);
        }
      } catch (error) {
        console.error("Error fetching wishlist properties:", error);
        res.status(500).send({ error: "Failed to fetch wishlist properties" });
      }
    });

    app.delete("/api/property-reviews/:id", async (req, res) => {
      const id = req.params.id;

      try {
        const result = await reviewsCollection.deleteOne({
          _id: new ObjectId(id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).send({ message: "Review not found" });
        }

        res.send({ success: true, message: "Review deleted successfully" });
      } catch (error) {
        console.error("Delete error:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    // update vertion of website

    app.patch("/properties/:id/wishlist", async (req, res) => {
      const propertyId = req.params.id;
      const { wishlistStatus, wishlistUser } = req.body;

      try {
        const result = await propertiesCollection.updateOne(
          { _id: new ObjectId(propertyId) },
          {
            $set: { wishlistStatus: wishlistStatus },
            $push: { wishlistUsersData: wishlistUser }, // Add one user to the array
          }
        );

        res.send(result);
      } catch (error) {
        console.error("Error updating wishlist:", error);
        res.status(500).send({ error: "Something went wrong" });
      }
    });

    app.get(
      "/wishlist-properties/:uid",
      verifyFirebaseToken,
      async (req, res) => {
        const userUID = req.params.uid;

        try {
          const result = await propertiesCollection
            .find({
              "wishlistUsersData.uid": userUID,
            })
            .toArray();

          res.send(result);
        } catch (error) {
          console.error("Error fetching wishlist properties:", error);
          res
            .status(500)
            .send({ error: "Failed to fetch wishlist properties" });
        }
      }
    );

    app.patch("/wishlist-properties/:propertyId/remove", async (req, res) => {
      const propertyId = req.params.propertyId;
      const { uid } = req.body;

      if (!uid) {
        return res.status(400).send({ error: "User UID is required" });
      }

      try {
        // First, get the current property to check wishlistUsersData length
        const property = await propertiesCollection.findOne({
          _id: new ObjectId(propertyId),
        });

        if (!property) {
          return res.status(404).send({ error: "Property not found" });
        }

        // Remove the user and update wishlistStatus in a single operation
        const updateOperation = {
          $pull: { wishlistUsersData: { uid: uid } },
        };

        // If this is the last user in the wishlist, set status to "false"
        if (property.wishlistUsersData?.length === 1) {
          updateOperation.$set = { wishlistStatus: "false" };
        }

        const result = await propertiesCollection.updateOne(
          { _id: new ObjectId(propertyId) },
          updateOperation
        );

        if (result.modifiedCount === 0) {
          return res.status(400).send({
            success: false,
            message: "User not found in wishlist or no changes made",
          });
        }

        res.send({
          success: true,
          message: "Removed from wishlist",
          wishlistStatus:
            property.wishlistUsersData?.length === 1 ? "false" : "true",
        });
      } catch (error) {
        console.error("Error removing from wishlist:", error);
        res.status(500).send({
          error: "Failed to remove from wishlist",
          details: error.message,
        });
      }
    });

    app.patch("/requested-properties/:propertyId/remove", async (req, res) => {
      const propertyId = req.params.propertyId;
      const { uid } = req.body;

      if (!uid) {
        return res.status(400).send({ error: "User UID is required" });
      }

      try {
        // First, get the current property to check wishlistUsersData length
        const property = await propertiesCollection.findOne({
          _id: new ObjectId(propertyId),
        });

        if (!property) {
          return res.status(404).send({ error: "Property not found" });
        }

        // Remove the user and update wishlistStatus in a single operation
        const updateOperation = {
          $pull: { requestedUserData: { uid: uid } },
        };

        // If this is the last user in the wishlist, set status to "false"
        if (property.requestedUserData?.length === 1) {
          updateOperation.$set = { wishlistStatus: "false" };
        }

        const result = await propertiesCollection.updateOne(
          { _id: new ObjectId(propertyId) },
          updateOperation
        );

        if (result.modifiedCount === 0) {
          return res.status(400).send({
            success: false,
            message: "User not found in wishlist or no changes made",
          });
        }

        res.send({
          success: true,
          message: "Removed from wishlist",
          wishlistStatus:
            property.wishlistUsersData?.length === 1 ? "false" : "true",
        });
      } catch (error) {
        console.error("Error removing from wishlist:", error);
        res.status(500).send({
          error: "Failed to remove from wishlist",
          details: error.message,
        });
      }
    });

    app.patch("/make-offer/:id", async (req, res) => {
      const propertyId = req.params.id;
      const userRequestData = req.body;

      if (!propertyId || !userRequestData?.uid) {
        return res.status(400).json({ message: "Invalid request data" });
      }

      try {
        const property = await propertiesCollection.findOne({
          _id: new ObjectId(propertyId),
        });

        if (!property) {
          return res.status(404).json({ message: "Property not found" });
        }

        const updateOperation = {
          $set: { requestStatus: "pending" },
          $addToSet: { requestedUserData: userRequestData }, // Prevents duplicates
          $pull: { wishlistUsersData: { uid: userRequestData.uid } },
        };

        // If this user is the last one in wishlistUsersData, update the status too
        if (
          Array.isArray(property.wishlistUsersData) &&
          property.wishlistUsersData.length === 1 &&
          property.wishlistUsersData[0].uid === userRequestData.uid
        ) {
          updateOperation.$set.wishlistStatus = "false";
        }

        const result = await propertiesCollection.updateOne(
          { _id: new ObjectId(propertyId) },
          updateOperation
        );

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .json({ message: "Property not updated or data already present" });
        }

        res
          .status(200)
          .json({ message: "Offer submitted and wishlist updated" });
      } catch (err) {
        console.error("Error in /make-offer:", err);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    app.get(
      "/api/properties/requested/:creatorEmail",
      verifyFirebaseToken,
      async (req, res) => {
        const creatorEmail = req.params.creatorEmail;
        const requestStatus = req.query.requestStatus;

        try {
          // Build query object
          const query = { creatorEmail };

          if (requestStatus) {
            query.requestStatus = requestStatus;
          }

          const properties = await propertiesCollection.find(query).toArray();
          res.send(properties);
        } catch (error) {
          console.error("Error fetching requested properties:", error);
          res
            .status(500)
            .send({ error: "Failed to fetch requested properties." });
        }
      }
    );

    app.patch("/api/properties/requestStatus/:id", async (req, res) => {
      const propertyId = req.params.id;
      const userEmailToRemove = req.query.email;
      const { requestStatus } = req.body;

      if (!userEmailToRemove) {
        return res
          .status(400)
          .send({ error: "Email query parameter is required" });
      }

      try {
        const result = await propertiesCollection.updateOne(
          { _id: new ObjectId(propertyId) },
          {
            $set: { requestStatus },
            $pull: { requestedUserData: { email: userEmailToRemove } },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ error: "Property not found" });
        }

        res.send({
          success: true,
          message: "Request status updated and user removed successfully",
        });
      } catch (error) {
        console.error("Error updating property:", error);
        res.status(500).send({ error: "Failed to update property" });
      }
    });

    app.patch("/api/properties/accept-request/:id", async (req, res) => {
      const propertyId = req.params.id;

      try {
        // First verify the property exists and is in pending status
        const property = await propertiesCollection.findOne({
          _id: new ObjectId(propertyId),
          requestStatus: "pending",
        });

        if (!property) {
          return res.status(404).json({
            success: false,
            message: "Property not found or not in pending status",
          });
        }

        // Update the status to accepted
        const result = await propertiesCollection.updateOne(
          { _id: new ObjectId(propertyId) },
          { $set: { requestStatus: "accepted" } }
        );

        if (result.modifiedCount === 0) {
          return res.status(400).json({
            success: false,
            message: "No changes made - property may already be accepted",
          });
        }

        res.status(200).json({
          success: true,
          message: "Property request accepted successfully",
        });
      } catch (error) {
        console.error("Error accepting property request:", error);
        res.status(500).json({
          success: false,
          message: "Failed to accept property request",
          error: error.message,
        });
      }
    });

    app.get(
      "/api/properties/user-requests/:userId",
      verifyFirebaseToken,
      async (req, res) => {
        try {
          const userId = req.params.userId;

          if (!userId) {
            return res.status(400).json({
              success: false,
              message: "User ID is required",
            });
          }

          // MongoDB query: Match properties with pending requestStatus
          // AND where requestedUserData array has an object with uid === userId
          const query = {
            requestStatus: "accepted",
            requestedUserData: {
              $elemMatch: {
                uid: userId,
              },
            },
          };

          const properties = await propertiesCollection.find(query).toArray();

          // Optional: Attach the user's request details only (if needed)
          const enhancedProperties = properties.map((property) => {
            const userRequest = property.requestedUserData.find(
              (request) => request.uid === userId
            );

            return {
              ...property,
              userRequestDetails: userRequest,
            };
          });

          res.status(200).json(enhancedProperties);
        } catch (error) {
          console.error("Error fetching properties for user:", error);
          res.status(500).json({
            success: false,
            message: "Failed to fetch properties",
            error: error.message,
          });
        }
      }
    );

    app.patch(
      "/api/properties/admin-approval/:id/:status",
      async (req, res) => {
        const { id, status } = req.params;

        // Validate status
        if (status !== "true" && status !== "false") {
          return res.status(400).send({
            error: "Invalid status value. Must be 'true' or 'false'.",
          });
        }

        try {
          const result = await propertiesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { adminApproval: status } }
          );

          if (result.matchedCount === 0) {
            return res.status(404).send({ error: "Property not found" });
          }

          res.send({
            success: true,
            message: `adminApproval status updated to ${status}`,
          });
        } catch (error) {
          console.error("Error updating adminApproval:", error);
          res.status(500).send({ error: "Internal server error" });
        }
      }
    );

    app.patch("/api/user-role-update/:id/:status", async (req, res) => {
      const { id, status } = req.params;

      try {
        const result = await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role: status } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ error: "User not found" });
        }

        res.send({
          success: true,
          message: `user role updated status for ${status}`,
        });
      } catch (error) {
        console.error("Error updating:", error);
        res.status(500).send({ error: "Internal server error" });
      }
    });

    app.get("/api/all-users", verifyFirebaseToken, async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    });

    app.delete("/api/users/:uid", verifyFirebaseToken, async (req, res) => {
      const uid = req.params.uid;

      try {
        // Delete from Firebase Auth
        await admin.auth().deleteUser(uid);

        // Delete from your MongoDB user collection
        const result = await userCollection.deleteOne({ uid });

        if (result.deletedCount === 0) {
          return res.status(404).send({ message: "User not found in DB" });
        }

        res.send({ success: true, message: "User deleted successfully" });
      } catch (error) {
        console.error("Error deleting user:", error);
        res.status(500).send({ error: "Failed to delete user" });
      }
    });

    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Do not close the client here to keep the server alive
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  try {
    res.send("Hello World!");
  } catch (error) {
    console.error("Error in root route:", error);
    res.status(500).send({ error: "Something went wrong" });
  }
});

app.listen(port, () => {
  console.log(`Express app listening on port ${port}`);
});
